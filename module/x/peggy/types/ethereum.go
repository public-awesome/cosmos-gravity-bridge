package types

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"

	sdk "github.com/cosmos/cosmos-sdk/types"
	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

const EthereumAddressLength = gethCommon.AddressLength

var isValidETHAddress = regexp.MustCompile("^0x[0-9a-fA-F]{40}$").MatchString
var emptyAddr [EthereumAddressLength]byte

// EthereumAddress defines a standard ethereum address
type EthereumAddress gethCommon.Address

// NewEthereumAddress is a constructor function for EthereumAddress
func NewEthereumAddress(address string) EthereumAddress {
	e := EthereumAddress(gethCommon.HexToAddress(address))
	return e //, e.ValidateBasic() // TODO: check and return error
}

func (e EthereumAddress) String() string {
	return gethCommon.Address(e).String()
}

// Bytes return the encoded address string as bytes
func (e EthereumAddress) Bytes() []byte {
	return []byte(e.String())
}

// RawBytes return the unencoded address bytes
func (e EthereumAddress) RawBytes() []byte {
	return e[:]
}

func (e EthereumAddress) ValidateBasic() error {
	if !isValidETHAddress(e.String()) {
		return ErrInvalid
	}
	return nil
}

func (e EthereumAddress) IsEmpty() bool {
	return emptyAddr == e
}

// MarshalJSON marshals the ethereum address to JSON
func (e EthereumAddress) MarshalJSON() ([]byte, error) {
	if e.IsEmpty() {
		return []byte(`""`), nil
	}
	return []byte(fmt.Sprintf("%q", e.String())), nil
}

// UnmarshalJSON unmarshals an ethereum address
func (e *EthereumAddress) UnmarshalJSON(input []byte) error {
	if string(input) == `""` {
		return nil
	}
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(gethCommon.Address{}), input, e[:])
}

func (e EthereumAddress) LessThan(o EthereumAddress) bool {
	return bytes.Compare(e[:], o[:]) == -1
}

func NewERC20Token(amount sdk.Int, symbol string, tokenContractAddress []byte) *ERC20Token {
	return &ERC20Token{Amount: amount, Symbol: symbol, TokenContractAddress: tokenContractAddress}
	// return ERC20Token{Amount: sdk.NewInt(int64(amount)), Symbol: symbol, TokenContractAddress: tokenContractAddress}
}

// AsVoucherCoin converts the data into a cosmos coin with peggy voucher denom.
func (e *ERC20Token) AsVoucherCoin() sdk.Coin {
	// return sdk.NewInt64Coin(NewVoucherDenom(e.TokenContractAddress, e.Symbol).String(), e.Amount.Int64())
	return sdk.NewCoin(NewVoucherDenom(e.TokenContractAddress, e.Symbol).String(), e.Amount)
}

func (t *ERC20Token) Add(o *ERC20Token) *ERC20Token {
	if t.Symbol != o.Symbol {
		panic("invalid symbol")
	}
	if string(t.TokenContractAddress) != string(o.TokenContractAddress) {
		panic("invalid contract address")
	}
	// TODO: this needs to be fixed to prevent overflows !!!
	// sum := t.Amount.Add(o.Amount)
	sum := o.Amount.Add(t.Amount)
	// if !sum.IsUint64() {
	// 	panic("invalid amount")
	// }
	return NewERC20Token(sum, t.Symbol, t.TokenContractAddress)
}
