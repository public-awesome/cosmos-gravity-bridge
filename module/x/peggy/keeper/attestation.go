package keeper

import (
	"fmt"
	"strconv"

	"github.com/althea-net/peggy/module/x/peggy/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) Testify(ctx sdk.Context, claim types.EthereumClaim) (*types.Attestation, error) {
	// Check that the nonce of this event is exactly one higher than the last nonce stored by this validator.
	// We check the event nonce in processAttestation as well, but checking it here gives individual eth signers a chance to retry,
	// and prevents validators from submitting two claims with the same nonce
	lastEventNonce := k.GetLastEventNonceByValidator(ctx, sdk.ValAddress(claim.GetClaimer()))
	if claim.GetEventNonce() != lastEventNonce+1 {
		return nil, types.ErrNonContiguousEventNonce
	}
	valAddr := k.GetOrchestratorValidator(ctx, claim.GetClaimer())
	if valAddr == nil {
		panic("Could not find ValAddr for delegate key, should be checked by now")
	}
	k.setLastEventNonceByValidator(ctx, valAddr, claim.GetEventNonce())

	// Tries to get an attestation with the same eventNonce and claim as the claim that was submitted.
	att := k.GetAttestation(ctx, claim.GetEventNonce(), claim.ClaimHash())

	// If it does not exist, create a new one.
	if att == nil {
		att = &types.Attestation{
			Observed: false,
		}
		any, err := codectypes.NewAnyWithValue(att)
		if err != nil {
			return nil, err
		}
		att.Claim = any
	}

	// Add the validator's vote to this attestation
	att.Votes = append(att.Votes, valAddr.String())

	// Update the block height
	att.Height = uint64(ctx.BlockHeight())

	k.SetAttestation(ctx, claim.GetEventNonce(), claim.ClaimHash(), att)

	return att, nil
}

// TryAttestation checks if an attestation has enough votes to be applied to the consensus state
// and has not already been marked Observed, then calls processAttestation to actually apply it to the state,
// and then marks it Observed and emits an event.
func (k Keeper) TryAttestation(ctx sdk.Context, att *types.Attestation) {
	claim, ok := att.Claim.GetCachedValue().(types.EthereumClaim)
	if !ok {
		// TODO-JT panic or error here?
		return
	}

	// If the attestation has not yet been Observed, sum up the votes and see if it is ready to apply to the state.
	// This conditional stops the attestation from accidentally being applied twice.
	if !att.Observed {
		// Sum the current powers of all validators who have voted and see if it passes the current threshold
		// TODO: The different integer types and math here needs a careful review
		totalPower := k.StakingKeeper.GetLastTotalPower(ctx)
		requiredPower := types.AttestationVotesPowerThreshold.Mul(totalPower).Quo(sdk.NewInt(100))
		attestationPower := sdk.NewInt(0)
		for _, validator := range att.Votes {
			val, err := sdk.ValAddressFromBech32(validator)
			if err != nil {
				panic(err)
			}
			validatorPower := k.StakingKeeper.GetLastValidatorPower(ctx, val)
			// Add it to the attestation power's sum
			attestationPower = attestationPower.Add(sdk.NewInt(validatorPower))
			// If the power of all the validators that have voted on the attestation is higher or equal to the threshold,
			// process the attestation, set Observed to true, and break
			if attestationPower.GTE(requiredPower) {
				k.processAttestation(ctx, att, claim)
				att.Observed = true
				k.emitObservedEvent(ctx, att, claim)
				break
			}
		}
	}
}

// processAttestation actually applies the attestation to the consensus state
func (k Keeper) processAttestation(ctx sdk.Context, att *types.Attestation, claim types.EthereumClaim) {
	lastEventNonce := k.GetLastObservedEventNonce(ctx)
	if claim.GetEventNonce() != uint64(lastEventNonce)+1 {
		panic("attempting to apply events to state out of order")
	}
	k.setLastObservedEventNonce(ctx, claim.GetEventNonce())

	// then execute in a new Tx so that we can store state on failure
	xCtx, commit := ctx.CacheContext()
	if err := k.AttestationHandler.Handle(xCtx, *att, claim); err != nil { // execute with a transient storage
		// If the attestation fails, something has gone wrong and we can't recover it. Log and move on
		// The attestation will still be marked "Observed", and validators can still be slashed for not
		// having voted for it.
		k.logger(ctx).Error("attestation failed",
			"cause", err.Error(),
			"claim type", claim.GetType(),
			"id", types.GetAttestationKey(claim.GetEventNonce(), claim.ClaimHash()),
			"nonce", fmt.Sprint(claim.GetEventNonce()),
		)
	} else {
		commit() // persist transient storage

		// TODO: after we commit, delete the outgoingtxbatch that this claim references
	}
}

// emitObservedEvent emits an event with information about an attestation that has been applied to
// consensus state.
func (k Keeper) emitObservedEvent(ctx sdk.Context, att *types.Attestation, claim types.EthereumClaim) {
	observationEvent := sdk.NewEvent(
		types.EventTypeObservation,
		sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		sdk.NewAttribute(types.AttributeKeyAttestationType, string(claim.GetType())),
		sdk.NewAttribute(types.AttributeKeyContract, k.GetBridgeContractAddress(ctx)),
		sdk.NewAttribute(types.AttributeKeyBridgeChainID, strconv.Itoa(int(k.GetBridgeChainID(ctx)))),
		sdk.NewAttribute(types.AttributeKeyAttestationID, string(types.GetAttestationKey(claim.GetEventNonce(), claim.ClaimHash()))), // todo: serialize with hex/ base64 ?
		sdk.NewAttribute(types.AttributeKeyNonce, fmt.Sprint(claim.GetEventNonce())),
		// TODO: do we want to emit more information?
	)
	ctx.EventManager().EmitEvent(observationEvent)
}

// SetAttestation sets the attestation in the store
func (k Keeper) SetAttestation(ctx sdk.Context, eventNonce uint64, claimHash []byte, att *types.Attestation) {
	store := ctx.KVStore(k.storeKey)
	// att.ClaimHash = claim.ClaimHash()
	// att.Height = uint64(ctx.BlockHeight())
	aKey := types.GetAttestationKey(eventNonce, claimHash)
	store.Set(aKey, k.cdc.MustMarshalBinaryBare(att))
}

// SetAttestationUnsafe sets the attestation w/o setting height and claim hash
func (k Keeper) SetAttestationUnsafe(ctx sdk.Context, eventNonce uint64, claimHash []byte, att *types.Attestation) {
	store := ctx.KVStore(k.storeKey)
	aKey := types.GetAttestationKeyWithHash(eventNonce, claimHash)
	store.Set(aKey, k.cdc.MustMarshalBinaryBare(att))
}

// GetAttestation return an attestation given a nonce
func (k Keeper) GetAttestation(ctx sdk.Context, eventNonce uint64, claimHash []byte) *types.Attestation {
	store := ctx.KVStore(k.storeKey)
	aKey := types.GetAttestationKey(eventNonce, claimHash)
	bz := store.Get(aKey)
	if len(bz) == 0 {
		return nil
	}
	var att types.Attestation
	k.cdc.MustUnmarshalBinaryBare(bz, &att)
	return &att
}

// DeleteAttestation deletes an attestation given an event nonce and claim
func (k Keeper) DeleteAttestation(ctx sdk.Context, eventNonce uint64, claimHash []byte, att *types.Attestation) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetAttestationKeyWithHash(eventNonce, claimHash))
}

// GetAttestationMapping returns a mapping of eventnonce -> attestations at that nonce
func (k Keeper) GetAttestationMapping(ctx sdk.Context) (out map[uint64][]types.Attestation) {
	out = make(map[uint64][]types.Attestation)
	k.IterateAttestaions(ctx, func(_ []byte, att types.Attestation) bool {
		claim, ok := att.Claim.GetCachedValue().(types.EthereumClaim)
		// TODO-JT panic if not ok?
		if !ok {
			panic("couldn't cast to claim")
		}

		if val, ok := out[claim.GetEventNonce()]; !ok {
			out[claim.GetEventNonce()] = []types.Attestation{att}
		} else {
			out[claim.GetEventNonce()] = append(val, att)
		}
		return false
	})
	return
}

// IterateAttestaions iterates through all attestations
func (k Keeper) IterateAttestaions(ctx sdk.Context, cb func([]byte, types.Attestation) bool) {
	store := ctx.KVStore(k.storeKey)
	prefix := []byte(types.OracleAttestationKey)
	iter := store.Iterator(prefixRange(prefix))
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		att := types.Attestation{}
		k.cdc.MustUnmarshalBinaryBare(iter.Value(), &att)
		// cb returns true to stop early
		if cb(iter.Key(), att) {
			return
		}
	}
}

// GetLastObservedEventNonce returns the latest observed event nonce
func (k Keeper) GetLastObservedEventNonce(ctx sdk.Context) uint64 {
	store := ctx.KVStore(k.storeKey)
	bytes := store.Get(types.LastObservedEventNonceKey)

	if len(bytes) == 0 {
		return 0
	}
	return types.UInt64FromBytes(bytes)
}

// setLastObservedEventNonce sets the latest observed event nonce
func (k Keeper) setLastObservedEventNonce(ctx sdk.Context, nonce uint64) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.LastObservedEventNonceKey, types.UInt64Bytes(nonce))
}

// GetLastEventNonceByValidator returns the latest event nonce for a given validator
func (k Keeper) GetLastEventNonceByValidator(ctx sdk.Context, validator sdk.ValAddress) uint64 {
	store := ctx.KVStore(k.storeKey)
	bytes := store.Get(types.GetLastEventNonceByValidatorKey(validator))

	if len(bytes) == 0 {
		return 0
	}
	return types.UInt64FromBytes(bytes)
}

// setLastEventNonceByValidator sets the latest event nonce for a give validator
func (k Keeper) setLastEventNonceByValidator(ctx sdk.Context, validator sdk.ValAddress, nonce uint64) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetLastEventNonceByValidatorKey(validator), types.UInt64Bytes(nonce))
}
