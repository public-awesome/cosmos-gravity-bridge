package types

import (
	"encoding/hex"
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/crypto"
)

func NewMsgValsetConfirm(nonce uint64, eth_address []byte, validator string, signature string) MsgValsetConfirm {
	return MsgValsetConfirm{
		Nonce:      nonce,
		Validator:  validator,
		EthAddress: eth_address,
		Signature:  signature,
	}
}

// Route should return the name of the module
func (msg MsgValsetConfirm) Route() string { return RouterKey }

// Type should return the action
func (msg MsgValsetConfirm) Type() string { return "valset_confirm" }

// Stateless checks
func (msg MsgValsetConfirm) ValidateBasic() error {
	if msg.Validator == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, msg.Validator)
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgValsetConfirm) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgValsetConfirm) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Validator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

func NewMsgValsetRequest(requester sdk.AccAddress) MsgValsetRequest {
	return MsgValsetRequest{
		Requester: requester.String(),
	}
}

// Route should return the name of the module
func (msg MsgValsetRequest) Route() string { return RouterKey }

// Type should return the action
func (msg MsgValsetRequest) Type() string { return "valset_request" }

func (msg MsgValsetRequest) ValidateBasic() error { return nil }

// GetSignBytes encodes the message for signing
func (msg MsgValsetRequest) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgValsetRequest) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Requester)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

func NewMsgSetEthAddress(address []byte, validator string, signature string) MsgSetEthAddress {
	return MsgSetEthAddress{
		Address:   address,
		Validator: validator,
		Signature: signature,
	}
}

// Route should return the name of the module
func (msg MsgSetEthAddress) Route() string { return RouterKey }

// Type should return the action
func (msg MsgSetEthAddress) Type() string { return "set_eth_address" }

// ValidateBasic runs stateless checks on the message
// Checks if the Eth address is valid, and whether the Eth address has signed the validator address
// (proving control of the Eth address)
func (msg MsgSetEthAddress) ValidateBasic() error {
	if msg.Validator == "" {
		return sdkerrors.Wrap(ErrEmpty, "validator")
	}
	if _, err := sdk.ValAddressFromBech32(msg.Validator); err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "validator")
	}

	// TODO: reimplement eth address validation ideally there is a constructor and a type
	// if err := msg.Address.ValidateBasic(); err != nil {
	// 	return sdkerrors.Wrap(err, "ethereum address")
	// }

	sigBytes, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "Could not decode hex string %s", msg.Signature)
	}

	err = ValidateEthereumSignature(crypto.Keccak256([]byte(msg.Validator)), sigBytes, string(msg.Address))
	if err != nil {
		return sdkerrors.Wrapf(err, "digest: %x sig: %x address %s error: %s", crypto.Keccak256([]byte(msg.Validator)), msg.Signature, msg.Address, err.Error())
	}

	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSetEthAddress) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSetEthAddress) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Validator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

func NewMsgSendToEth(sender string, destAddress []byte, send sdk.Coin, bridgeFee sdk.Coin) MsgSendToEth {
	return MsgSendToEth{
		Sender:      sender,
		DestAddress: destAddress,
		Amount:      send,
		BridgeFee:   bridgeFee,
	}
}

// Route should return the name of the module
func (msg MsgSendToEth) Route() string { return RouterKey }

// Type should return the action
func (msg MsgSendToEth) Type() string { return "send_to_eth" }

// ValidateBasic runs stateless checks on the message
// Checks if the Eth address is valid
func (msg MsgSendToEth) ValidateBasic() error {
	// fee and send must be of the same denom
	if msg.Amount.Denom != msg.BridgeFee.Denom {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "fee and amount must be the same type")
	}
	if !IsVoucherDenom(msg.Amount.Denom) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "amount is not a voucher type")
	}
	if !IsVoucherDenom(msg.BridgeFee.Denom) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "fee is not a voucher type")
	}
	if !msg.Amount.IsValid() || msg.Amount.IsZero() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "amount")
	}
	if !msg.BridgeFee.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "fee")
	}
	// TODO validate eth address
	// TODO for demo get single allowed demon from the store
	// TODO validate fee is sufficient, fixed fee to start
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgSendToEth) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgSendToEth) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

func NewMsgRequestBatch(requester string) MsgRequestBatch {
	return MsgRequestBatch{
		Requester: requester,
	}
}

// Route should return the name of the module
func (msg MsgRequestBatch) Route() string { return RouterKey }

// Type should return the action
func (msg MsgRequestBatch) Type() string { return "request_batch" }

func (msg MsgRequestBatch) ValidateBasic() error {
	// TODO ensure that Demon matches hardcoded allowed value
	// TODO later make sure that Demon matches a list of tokens already
	// in the bridge to send
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgRequestBatch) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgRequestBatch) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Requester)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

func NewMsgConfirmBatch(nonce uint64, validator string, signature string) MsgConfirmBatch {
	return MsgConfirmBatch{
		Nonce:     nonce,
		Validator: validator,
		Signature: signature,
	}
}

// Route should return the name of the module
func (msg MsgConfirmBatch) Route() string { return RouterKey }

// Type should return the action
func (msg MsgConfirmBatch) Type() string { return "confirm_batch" }

func (msg MsgConfirmBatch) ValidateBasic() error {
	// TODO validate signature
	// TODO get batch from storage
	// TODO generate batch in storage on MsgRequestBatch in the first place
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgConfirmBatch) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgConfirmBatch) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Validator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

type EthereumClaim interface {
	GetEventNonce() uint64
	GetType() ClaimType
	ValidateBasic() error
	Details() AttestationDetails
}

var (
	_ EthereumClaim = &EthereumBridgeDepositClaim{}
	_ EthereumClaim = &EthereumBridgeWithdrawalBatchClaim{}
)

// NoUniqueClaimDetails is a NIL object to
var NoUniqueClaimDetails AttestationDetails = nil

func (e *EthereumBridgeDepositClaim) GetType() ClaimType {
	return CLAIM_TYPE_ETHEREUM_BRIDGE_DEPOSIT
}

func (e *EthereumBridgeDepositClaim) ValidateBasic() error {
	// todo: validate all fields
	return nil
}

func (e *EthereumBridgeDepositClaim) GetEventNonce() uint64 {
	return e.Nonce
}

func (e *EthereumBridgeDepositClaim) Details() AttestationDetails {
	return BridgeDeposit{
		Erc_20Token:    e.Erc20Token,
		EthereumSender: e.EthereumSender,
		CosmosReceiver: e.CosmosReceiver,
	}
}

func (e *EthereumBridgeWithdrawalBatchClaim) GetType() ClaimType {
	return CLAIM_TYPE_ETHEREUM_BRIDGE_WITHDRAWAL_BATCH
}

func (e *EthereumBridgeWithdrawalBatchClaim) ValidateBasic() error {
	// TODO: validate the things
	return nil
}

func (e *EthereumBridgeWithdrawalBatchClaim) Details() AttestationDetails {
	return NoUniqueClaimDetails
}

const (
	TypeMsgCreateEthereumClaims = "create_eth_claims"
)

var (
	_ sdk.Msg = &MsgCreateEthereumClaims{}
)

func NewMsgCreateEthereumClaims(ethereumChainID uint64, bridgeContractAddress []byte, orchestrator string, claims []*codectypes.Any) *MsgCreateEthereumClaims {
	return &MsgCreateEthereumClaims{EthereumChainId: ethereumChainID, BridgeContractAddress: bridgeContractAddress, Orchestrator: orchestrator, Claims: claims}
}

func (m MsgCreateEthereumClaims) Route() string {
	return RouterKey
}

func (m MsgCreateEthereumClaims) Type() string {
	return TypeMsgCreateEthereumClaims
}

func (m MsgCreateEthereumClaims) ValidateBasic() error {
	// todo: validate all fields
	if _, err := sdk.ValAddressFromBech32(m.Orchestrator); err != nil {
		return sdkerrors.Wrap(err, "orchestrator")
	}
	for i, c := range m.Claims {
		claim, err := UnpackEthereumClaim(c)
		if err != nil {
			return sdkerrors.Wrap(err, "failed to unpack EthereumClaim")
		}
		if err := claim.ValidateBasic(); err != nil {
			return sdkerrors.Wrapf(err, "claim %d failed ValidateBasic()", i)
		}
	}
	return nil
}

func (m MsgCreateEthereumClaims) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(m)
	return sdk.MustSortJSON(bz)
}

func (m MsgCreateEthereumClaims) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(m.Orchestrator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}

// Route should return the name of the module
func (msg MsgBridgeSignatureSubmission) Route() string { return RouterKey }

// Type should return the action
func (msg MsgBridgeSignatureSubmission) Type() string { return "valset_confirm" }

// Stateless checks
func (msg MsgBridgeSignatureSubmission) ValidateBasic() error {
	if msg.Nonce == 0 {
		return fmt.Errorf("nonce")
	}
	if !IsSignType(msg.SignType) {
		return sdkerrors.Wrap(ErrInvalid, "sign type")
	}
	if msg.Orchestrator == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, msg.Orchestrator)
	}
	if _, err := sdk.ValAddressFromBech32(msg.Orchestrator); err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "validator")
	}
	if len(msg.EthereumSignature) == 0 {
		return sdkerrors.Wrap(ErrEmpty, "signature")
	}
	return nil
}

// GetSignBytes encodes the message for signing
func (msg MsgBridgeSignatureSubmission) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(msg))
}

// GetSigners defines whose signature is required
func (msg MsgBridgeSignatureSubmission) GetSigners() []sdk.AccAddress {
	addr, err := sdk.AccAddressFromBech32(msg.Orchestrator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{addr}
}
