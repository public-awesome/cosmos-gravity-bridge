package keeper

import (
	"sort"

	"github.com/althea-net/peggy/module/x/peggy/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper maintains the link to storage and exposes getter/setter methods for the various parts of the state machine
type Keeper struct {
	StakingKeeper types.StakingKeeper

	storeKey sdk.StoreKey // Unexposed key to access store from sdk.Context

	cdc *codec.Codec // The wire codec for binary encoding/decoding.
}

// NewKeeper creates new instances of the nameservice Keeper
func NewKeeper(cdc *codec.Codec, storeKey sdk.StoreKey, stakingKeeper types.StakingKeeper) Keeper {
	return Keeper{
		cdc:           cdc,
		storeKey:      storeKey,
		StakingKeeper: stakingKeeper,
	}
}

// GetValsetIndex gets the valset index if it exists, other wise it returns
// an empty map
func (k Keeper) GetValsetIndex(ctx sdk.Context) types.ValsetIndex {
	store := ctx.KVStore(k.storeKey)
	val := store.Get(types.GetValsetIndexKey())
	if val != nil {
		index := types.ValsetIndex{}
		k.cdc.MustUnmarshalBinaryBare(val, &index)
		return index
	}
	return types.ValsetIndex{
		ValsetRequests:      make(map[int64]types.Valset),
		ValsetConfirmations: make(map[int64]map[*sdk.AccAddress]types.ValsetIndexEntry),
	}

}

// SetValsetIndex saves the provided ValsetIndex
func (k Keeper) SetValsetIndex(ctx sdk.Context, updated types.ValsetIndex) {
	store := ctx.KVStore(k.storeKey)
	val := store.Get(types.GetValsetIndexKey())
	store.Set(types.GetValsetIndexKey(), k.cdc.MustMarshalBinaryBare(val))
}

// AddRequestToValsetIndex is meant to be called in parallel to
// SetValsetRequest and it stores that a request has been made into store
// in such a way that it can be easily found in the future. It requires no
// extra arguments as like SetValsetRequest it grabs everything it needs elsewhere.
func (k Keeper) AddRequestToValsetIndex(ctx sdk.Context) {
	valset := k.GetCurrentValset(ctx)
	index := k.GetValsetIndex(ctx)
	nonce := ctx.BlockHeight()
	valset.Nonce = nonce
	index.ValsetRequests[nonce] = valset
	k.SetValsetIndex(ctx, index)
}

// AddConfirmToValsetIndex is meant to be called in parallel to SetValsetConfirm
// it stores the signature provided for easy indexing
func (k Keeper) AddConfirmToValsetIndex(ctx sdk.Context, confirmation types.MsgValsetConfirm) {
	var index = k.GetValsetIndex(ctx)
	var ethAddress = k.GetEthAddress(ctx, confirmation.Validator)
	valset, exists := index.ValsetRequests[confirmation.Nonce]
	if !exists {
		// this can't happen, it would fail validation at sig verification
		panic("ValsetConfirm submitted for nonce that does not have a request!")
	}

}

func (k Keeper) SetValsetRequest(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)
	valset := k.GetCurrentValset(ctx)
	nonce := ctx.BlockHeight()
	valset.Nonce = nonce
	store.Set(types.GetValsetRequestKey(nonce), k.cdc.MustMarshalBinaryBare(valset))
}

func (k Keeper) GetValsetRequest(ctx sdk.Context, nonce int64) *types.Valset {
	store := ctx.KVStore(k.storeKey)

	store_bytes := store.Get(types.GetValsetRequestKey(nonce))
	if store_bytes == nil {
		return nil
	}
	var valset types.Valset
	k.cdc.MustUnmarshalBinaryBare(store_bytes, &valset)
	return &valset
}

func (k Keeper) SetValsetConfirm(ctx sdk.Context, valsetConf types.MsgValsetConfirm) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetValsetConfirmKey(valsetConf.Nonce, valsetConf.Validator), k.cdc.MustMarshalBinaryBare(valsetConf))
}

func (k Keeper) GetValsetConfirm(ctx sdk.Context, nonce int64, validator sdk.AccAddress) *types.MsgValsetConfirm {
	store := ctx.KVStore(k.storeKey)
	entity := store.Get(types.GetValsetConfirmKey(nonce, validator))
	if entity == nil {
		return nil
	}
	confirm := types.MsgValsetConfirm{}
	k.cdc.MustUnmarshalBinaryBare(entity, &confirm)
	return &confirm
}

func (k Keeper) SetEthAddress(ctx sdk.Context, validator sdk.AccAddress, ethAddr string) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetEthAddressKey(validator), []byte(ethAddr))
}

func (k Keeper) GetEthAddress(ctx sdk.Context, validator sdk.AccAddress) string {
	store := ctx.KVStore(k.storeKey)
	val := store.Get(types.GetEthAddressKey(validator))
	return string(val)
}

type valsetSort types.Valset

func (a valsetSort) Len() int { return len(a.EthAddresses) }
func (a valsetSort) Swap(i, j int) {
	a.EthAddresses[i], a.EthAddresses[j] = a.EthAddresses[j], a.EthAddresses[i]
	a.Powers[i], a.Powers[j] = a.Powers[j], a.Powers[i]
}
func (a valsetSort) Less(i, j int) bool {
	// Secondary sort on eth address in case powers are equal
	if a.Powers[i] == a.Powers[j] {
		return a.EthAddresses[i] < a.EthAddresses[j]
	}
	return a.Powers[i] < a.Powers[j]
}

func (k Keeper) GetCurrentValset(ctx sdk.Context) types.Valset {
	validators := k.StakingKeeper.GetBondedValidatorsByPower(ctx)
	ethAddrs := make([]string, len(validators))
	powers := make([]int64, len(validators))
	for i, validator := range validators {
		validatorAddress := validator.GetOperator()
		p := k.StakingKeeper.GetLastValidatorPower(ctx, validatorAddress)
		powers[i] = p
		ethAddrs[i] = k.GetEthAddress(ctx, sdk.AccAddress(validatorAddress))
	}
	valset := types.Valset{EthAddresses: ethAddrs, Powers: powers}
	sort.Sort(valsetSort(valset))
	return valset
}
