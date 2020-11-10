package keeper

import (
	"github.com/althea-net/peggy/module/x/peggy/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// AttestationHandler processes `observed` Attestations
type AttestationHandler struct {
	keeper     Keeper
	bankKeeper types.BankKeeper
}

// Handle is the entry point for Attestation processing.
func (a AttestationHandler) Handle(ctx sdk.Context, att types.Attestation) error {
	details, err := types.UnpackAttestationDetails(att.Details)
	if err != nil {
		return err
	}
	switch att.ClaimType {
	case types.CLAIM_TYPE_ETHEREUM_BRIDGE_DEPOSIT:
		deposit, ok := details.(*types.BridgeDeposit)
		if !ok {
			return sdkerrors.Wrapf(types.ErrInvalid, "unexpected type: %T", att.Details)
		}
		if !a.keeper.HasCounterpartDenominator(ctx, types.NewVoucherDenom(deposit.Erc_20Token.TokenContractAddress, deposit.Erc_20Token.Symbol)) {
			a.keeper.StoreCounterpartDenominator(ctx, deposit.Erc_20Token.TokenContractAddress, deposit.Erc_20Token.Symbol)
		}
		coin := deposit.Erc_20Token.AsVoucherCoin()
		vouchers := sdk.Coins{coin}

		if err = a.bankKeeper.MintCoins(ctx, types.ModuleName, vouchers); err != nil {
			return sdkerrors.Wrapf(err, "mint vouchers coins: %s", vouchers)
		}
		recv, err := sdk.AccAddressFromBech32(deposit.CosmosReceiver)
		if err != nil {
			return sdkerrors.Wrap(err, "address")
		}
		if err = a.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, recv, vouchers); err != nil {
			return sdkerrors.Wrap(err, "transfer vouchers")
		}
	case types.CLAIM_TYPE_ETHEREUM_BRIDGE_WITHDRAWAL_BATCH:
		b := a.keeper.GetOutgoingTXBatch(ctx, att.EventNonce) // TODO: this is not the correct nonce. We need the batch nonce.
		if b == nil {
			return sdkerrors.Wrap(types.ErrUnknown, "nonce")
		}
		if err := b.Observed(); err != nil {
			return err
		}
		a.keeper.storeBatch(ctx, b)
		// cleanup outgoing TX pool
		for i := range b.Elements {
			a.keeper.removePoolEntry(ctx, b.Elements[i].Id)
		}
		// TODO: implement logic to free transactions from all earlier batches as well.
		return nil
	// case types.ClaimTypeEthereumBridgeMultiSigUpdate:
	// 	if !a.keeper.HasValsetRequest(ctx, att.EventNonce) {
	// 		return sdkerrors.Wrap(types.ErrUnknown, "nonce")
	// 	}

	// 	// todo: is there any cleanup for us like:
	// 	a.keeper.IterateValsetRequest(ctx, func(key []byte, _ types.Valset) bool {
	// 		nonce := types.UInt64NonceFromBytes(key)
	// 		if att.Nonce.GreaterThan(nonce) {
	// 			ctx.Logger().Info("TODO: let's remove valset request", "nonce", nonce)
	// 		}
	// 		// todo: also remove all confirmations < height
	// 		return false
	// 	})
	// 	return nil
	// case types.ClaimTypeEthereumBridgeBootstrap:
	// 	bootstrap, ok := att.Details.(types.BridgeBootstrap)
	// 	if !ok {
	// 		return sdkerrors.Wrapf(types.ErrInvalid, "unexpected type: %T", att.Details)
	// 	}
	// 	// quick hack:  we are storing the bootstrap data here to avoid the gov process in MVY.
	// 	// TODO: improve process by:
	// 	// - verify StartThreshold == params.StartThreshold
	// 	// - verify PeggyID == params.PeggyID

	// 	a.keeper.setPeggyID(ctx, bootstrap.PeggyID)
	// 	a.keeper.setStartThreshold(ctx, bootstrap.StartThreshold)

	// 	initialMultisigSet := types.NewValset(att.EventNonce, bootstrap.BridgeValidators)

	// 	// todo: do we want to do a sanity check that these validator addresses exits already?
	// 	// the peggy bridge can not operate proper without orchestrators having their ethereum
	// 	// addresses set before.
	// 	return a.keeper.SetBootstrapValset(ctx, initialMultisigSet)
	default:
		return sdkerrors.Wrapf(types.ErrInvalid, "event type: %s", att.ClaimType)
	}
	return nil
}
