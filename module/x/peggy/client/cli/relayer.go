package cli

import (
	"bufio"
	"bytes"
	stdcontext "context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/althea-net/peggy/module/x/peggy/keeper"
	"github.com/althea-net/peggy/module/x/peggy/types"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	authTypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethCommon "github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

const EthProvider = "http://localhost:8545"

type ERC20LogTransfer struct {
	From  common.Address
	To    common.Address
	Token *big.Int `abi:"value"`
}

type ERC20LogApproval struct {
	TokenOwner common.Address //`abi:"owner"`
	Spender    common.Address
	Token      *big.Int `abi:"value"`
}

type BridgeContractLogTransferOut struct {
	DepositNonce         *big.Int              `abi:"_nonce"`
	ERC20ContractAddress types.EthereumAddress `abi:"_erc20ContractAddress"`
	Symbol               string                `abi:"_symbol"`
	CosmosReceiver       string                `abi:"_destination"`
	Token                *big.Int              `abi:"_amount"`
}

type BridgeContractLogBootstrap struct {
	Nonce          *big.Int                `abi:"_nonce"`
	PeggyID        [32]byte                `abi:"_peggyId"`
	PowerThreshold *big.Int                `abi:"_powerThreshold"`
	Validators     []types.EthereumAddress `abi:"_validators"`
	Powers         []*big.Int              `abi:"_powers"`
}

type BridgeContractMultiSigUpdate struct {
	Nonce      *big.Int                `abi:"_nonce"`
	Validators []types.EthereumAddress `abi:"_validators"`
	Powers     []*big.Int              `abi:"_powers"`
}

type BridgeContractWithdrawalBatch struct {
	Nonce *big.Int `abi:"_nonce"`
}

func CmdUnsafeRelayer(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "relay [source_chain] [bridge_contract_address] [erc20_token_address] [eth_private_key]",
		Short: "Relay messages from source chain to the counterparty chain. Source can be 'eth' or 'cosmos'.  evm test addr: 0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)
			inBuf := bufio.NewReader(cmd.InOrStdin())
			txBldr := auth.NewTxBuilderFromCLI(inBuf).WithTxEncoder(utils.GetTxEncoder(cdc))

			cosmosAddr := cliCtx.GetFromAddress()

			client, err := ethclient.Dial(EthProvider)
			if err != nil {
				panic(err)
			}
			defer client.Close()
			fmt.Println("Started Ethereum connection with provider:", EthProvider)

			ctx := stdcontext.Background()
			ethereumChainID, err := client.NetworkID(ctx)
			if err != nil {
				panic(err)
			}
			println("+++ got chainID: ", ethereumChainID)

			sourceChain := args[0]
			bridgeContractAddress := args[1]
			erc20TokenAddress := args[2]
			privKeyString := args[3][2:]

			// Make Eth Signature over validator address
			ethPrivateKey, err := ethCrypto.HexToECDSA(privKeyString)
			if err != nil {
				return err
			}

			var (
				bridgeContractAddr = common.HexToAddress(bridgeContractAddress)
				erc20Addr          = common.HexToAddress(erc20TokenAddress) //bigPocketSender := common.HexToAddress("0xc783df8a850f42e7f7e57013759c285caa701eb6")
			)

			weiTokens, err := client.BalanceAt(ctx, erc20Addr, nil)
			if err != nil {
				panic(err)
			}
			fmt.Printf("++ erc20 contract owns tokens: %s\n", weiTokens.String())

			switch strings.ToLower(sourceChain) {
			case "eth":
				return relayFromETH(cliCtx, bridgeContractAddr, client, bridgeContractAddress, cosmosAddr, txBldr, ethereumChainID)
			case "cosmos":
				return relayFromCosmos(cliCtx, cdc, bridgeContractAddr, client, bridgeContractAddress, cosmosAddr, txBldr, ethereumChainID, ethPrivateKey)
			default:
				return errors.New("unsupported")
			}
		},
	}
}

const storeKey = "peggy"

func relayFromCosmos(cliCtx context.CLIContext, cdc *codec.Codec, bridgeContractAddr common.Address, client *ethclient.Client, bridgeContractAddress string, cosmosAddr sdk.AccAddress, txBldr authTypes.TxBuilder, ethereumChainID *big.Int, ethPrivateKey *ecdsa.PrivateKey) error {
	println("relay cosmos work")
	_, err := relayMultisigUpdates(cliCtx, cdc, bridgeContractAddr, client, ethPrivateKey)
	if err != nil {
		return err
	}
	println("relay batch")

	res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/inflightBatches", storeKey), nil)
	if err != nil {
		return sdkerrors.Wrap(err, "last approved nonce")
	}
	if len(res) == 0 {
		fmt.Println("Nothing found")
		return nil
	}
	var inflightBatches []keeper.ApprovedOutgoingTxBatchResponse
	cdc.MustUnmarshalJSON(res, &inflightBatches)

	oldValset, _, err := getLastObservedMultisigSet(cliCtx, cdc, res)
	if err != nil {
		return err
	}

	if len(inflightBatches) == 0 {
		fmt.Println("Nothing to do")
		return nil
	}
	for _, b := range inflightBatches {
		println("++ sending batch: " + b.Batch.Nonce.String())
		fmt.Printf("++ auth with multisig checkpoint: %X\n", oldValset.Valset.GetCheckpoint())
		//fmt.Printf("++ send with batch checkpoint: %X\n", b.Checkpoint)
		v, r, s := splitETHSignatures(b.Signatures)
		amounts := make([]*big.Int, len(b.Batch.Elements))
		destinations := make([]types.EthereumAddress, len(b.Batch.Elements))
		fees := make([]*big.Int, len(b.Batch.Elements))
		nonces := make([]*big.Int, len(b.Batch.Elements))
		for i, tx := range b.Batch.Elements {
			amounts[i] = big.NewInt(int64(tx.Amount.Amount))
			destinations[i] = tx.DestAddress
			fees[i] = big.NewInt(int64(tx.BridgeFee.Amount))
			nonces[i] = big.NewInt(int64(tx.ID)) // todo: is this a nonce that makes sense?
		}
		fmt.Printf("OOO valset: %#v\n", oldValset.Valset)
		fmt.Printf("OOO batch: %#v\n", b)

		fmt.Printf("++ valset %d == %d == %d ==%d == %d\n", len(asBigInts(oldValset.Valset.Powers)), len(v), len(r), len(s), len(b.Signatures))

		mData := []interface{}{
			// The validators that approve the batch
			oldValset.Valset.EthAddresses,
			asBigInts(oldValset.Valset.Powers),
			big.NewInt(int64(oldValset.Valset.Nonce.Uint64())),
			// These are arrays of the parts of the validators signatures
			v, r, s,
			// The batch of transactions
			amounts,
			destinations,
			fees,
			nonces,
			big.NewInt(int64(b.Batch.Nonce.Uint64())),
		}
		_, err = callBridgeContract(bridgeContractAddr, client, ethPrivateKey, "submitBatch", mData...)
		if err != nil {
			return err
		}

	}
	return nil
}

func relayMultisigUpdates(cliCtx context.CLIContext, cdc *codec.Codec, bridgeContractAddr common.Address, client *ethclient.Client, ethPrivateKey *ecdsa.PrivateKey) (*ethTypes.Transaction, error) {
	println("relaying multisig set updates")

	res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/lastApprovedMultiSigUpdate", storeKey), nil)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "last approved")
	}
	if len(res) == 0 {
		fmt.Println("Nothing found")
		return nil, nil
	}
	var newValset keeper.MultiSigUpdateResponse
	cdc.MustUnmarshalJSON(res, &newValset)

	oldValset, _, err := getLastObservedMultisigSet(cliCtx, cdc, res)
	if err != nil {
		return nil, err
	}
	if newValset.Valset.Nonce <= oldValset.Valset.Nonce {
		fmt.Println("Nothing to update")
		return nil, nil
	}

	fmt.Printf("++ auth with multisig checkpoint: %X\n", oldValset.Valset.GetCheckpoint())
	fmt.Printf("++ new multisig checkpoint: %X\n", newValset.Valset.GetCheckpoint())
	fmt.Printf("++ signatures: %#v\n", hex.EncodeToString(newValset.Signatures[0]))

	v, r, s := splitETHSignatures(newValset.Signatures)
	mData := []interface{}{
		newValset.Valset.EthAddresses,
		asBigInts(newValset.Valset.Powers),
		big.NewInt(int64(newValset.Valset.Nonce.Uint64())),
		oldValset.Valset.EthAddresses,
		asBigInts(oldValset.Valset.Powers),
		big.NewInt(int64(oldValset.Valset.Nonce.Uint64())),
		v, r, s,
	}
	return callBridgeContract(bridgeContractAddr, client, ethPrivateKey, "updateValset", mData...)
}

func getLastObservedMultisigSet(cliCtx context.CLIContext, cdc *codec.Codec, res []byte) (keeper.MultiSigUpdateResponse, *ethTypes.Transaction, error) {
	res, _, err := cliCtx.QueryWithData(fmt.Sprintf("custom/%s/lastObservedMultiSigUpdate", storeKey), nil)
	if err != nil {
		return keeper.MultiSigUpdateResponse{}, nil, sdkerrors.Wrap(err, "last observed")
	}
	if len(res) == 0 {
		fmt.Println("Nothing found")
		return keeper.MultiSigUpdateResponse{}, nil, nil
	}
	var oldValset keeper.MultiSigUpdateResponse
	cdc.MustUnmarshalJSON(res, &oldValset)
	return oldValset, nil, nil
}

func callBridgeContract(bridgeContractAddr common.Address, client *ethclient.Client, ethPrivateKey *ecdsa.PrivateKey, method string, mData ...interface{}) (*ethTypes.Transaction, error) {
	publicKey := ethPrivateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	gasPrice, err := client.SuggestGasPrice(stdcontext.Background())
	if err != nil {
		return nil, err
	}
	bridgeContractAbi, err := loadABI("../solidity/artifacts/Peggy.json")
	if err != nil {
		return nil, err
	}
	nonce, err := client.PendingNonceAt(stdcontext.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasLimit := uint64(300000) // in units
	amount := big.NewInt(0)    // in wei

	opts := bind.NewKeyedTransactor(ethPrivateKey)
	opts.Nonce = big.NewInt(int64(nonce))
	opts.Value = amount
	opts.GasPrice = gasPrice
	opts.GasLimit = gasLimit
	opts.Context = stdcontext.Background()
	instance := bind.NewBoundContract(bridgeContractAddr, *bridgeContractAbi, client, client, nil)

	tx, err := instance.Transact(opts, method, mData...)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "calling contract")
	}
	return tx, nil
}

func splitETHSignatures(signatures [][]byte) ([]byte, [][32]byte, [][32]byte) {
	multiSigLen := len(signatures)
	r := make([][32]byte, multiSigLen)
	s := make([][32]byte, multiSigLen)
	v := make([]byte, multiSigLen)

	for i := range signatures {
		r[i], s[i], v[i] = splitETHSignature(signatures[i])
	}
	return v, r, s
}

func splitETHSignature(raw []byte) (r [32]byte, s [32]byte, v byte) {
	if len(raw) != 65 {
		return
	}
	copy(r[:], raw[:32])
	copy(s[:], raw[32:64])
	v = raw[64] + 27
	return
}

func asBigInts(s []uint64) []*big.Int {
	r := make([]*big.Int, len(s))
	for i := range s {
		r[i] = big.NewInt(int64(s[i]))
	}
	return r
}

func relayFromETH(cliCtx context.CLIContext, bridgeContractAddr common.Address, client *ethclient.Client, bridgeContractAddress string, cosmosAddr sdk.AccAddress, txBldr authTypes.TxBuilder, ethereumChainID *big.Int) error {
	subQuery := ethereum.FilterQuery{
		Addresses: []common.Address{bridgeContractAddr /*erc20Addr */},
		Topics:    [][]common.Hash{},
	}

	erc20Abi, err := loadABI("../solidity/artifacts/IERC20.json")
	if err != nil {
		return err
	}
	bridgeContractAbi, err := loadABI("../solidity/artifacts/Peggy.json")
	if err != nil {
		return err
	}

	var (
		erc20LogTransferSigHash          = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")).Hex()
		erc20LogApprovalSigHash          = crypto.Keccak256Hash([]byte("Approval(address,address,uint256)")).Hex()
		bridgeContractLogTransferOut     = crypto.Keccak256Hash([]byte("TransferOutEvent(uint256,address,string,string,uint256)")).Hex()
		bridgeContractLogBootstrap       = crypto.Keccak256Hash([]byte("BootstrapEvent(uint256,bytes32,uint256,address[],uint256[])")).Hex()
		bridgeContractLogMultiSigUpdated = crypto.Keccak256Hash([]byte("ValsetUpdatedEvent(uint256,address[],uint256[])")).Hex()
		bridgeContractLogWithdrawalBatch = crypto.Keccak256Hash([]byte("WithdrawalBatchEvent(uint256)")).Hex()
	)
	logs, err := client.FilterLogs(stdcontext.Background(), subQuery)
	if err != nil {
		return err
	}

	for _, l := range logs {
		if l.Removed {
			panic("argh, can this happen?")
		}
		fmt.Println("------------------")
		fmt.Printf("Log Block Number: %d\n", l.BlockNumber)
		fmt.Printf("Log Index: %d\n", l.Index)

		switch l.Topics[0].Hex() {
		case bridgeContractLogBootstrap:
			fmt.Printf("[Bridge] Log Name: Bootstrap\n")
			var bootstrap BridgeContractLogBootstrap
			if err := bridgeContractAbi.Unpack(&bootstrap, "BootstrapEvent", l.Data); err != nil {
				return err
			}
			powers := make([]uint64, len(bootstrap.Powers))
			for i := range bootstrap.Powers {
				powers[i] = bootstrap.Powers[i].Uint64()
			}
			msg := types.MsgCreateEthereumClaims{
				EthereumChainID:       ethereumChainID.String(),
				BridgeContractAddress: types.NewEthereumAddress(bridgeContractAddress),
				Orchestrator:          cosmosAddr,
				Claims: []types.EthereumClaim{types.EthereumBridgeBootstrappedClaim{
					Nonce:               types.NewUInt64Nonce(bootstrap.Nonce.Uint64()),
					Block:               l.BlockNumber,
					AllowedValidatorSet: bootstrap.Validators,
					ValidatorPowers:     powers,
					PeggyID:             bootstrap.PeggyID[:],
					StartThreshold:      bootstrap.PowerThreshold.Uint64(),
				}},
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			txBldr = txBldr.WithGas(300000)
			if err := utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg}); err != nil {
				return err
			}

		case bridgeContractLogMultiSigUpdated:
			fmt.Printf("[Bridge] Log Name: MultiSig update\n")
			var multiSigUpdate BridgeContractMultiSigUpdate
			if err := bridgeContractAbi.Unpack(&multiSigUpdate, "ValsetUpdatedEvent", l.Data); err != nil {
				return err
			}
			powers := make([]uint64, len(multiSigUpdate.Powers))
			for i := range multiSigUpdate.Powers {
				powers[i] = multiSigUpdate.Powers[i].Uint64()
			}
			msg := types.MsgCreateEthereumClaims{
				EthereumChainID:       ethereumChainID.String(),
				BridgeContractAddress: types.NewEthereumAddress(bridgeContractAddress),
				Orchestrator:          cosmosAddr,
				Claims: []types.EthereumClaim{types.EthereumBridgeMultiSigUpdateClaim{
					Nonce: types.NewUInt64Nonce(multiSigUpdate.Nonce.Uint64()),
				}},
			}
			fmt.Printf("+++ confirming nonce: %s\n", multiSigUpdate.Nonce.String())

			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			if err := utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg}); err != nil {
				return err
			}

		case bridgeContractLogTransferOut:
			fmt.Printf("[Bridge] Log Name: Transfer Out. This is a deposit\n")
			var transferOutEvent BridgeContractLogTransferOut
			if err := bridgeContractAbi.Unpack(&transferOutEvent, "TransferOutEvent", l.Data); err != nil {
				return err
			}
			//transferOutEvent.CosmosReceiver = l.Topics[1].Hex()

			fmt.Printf("Token Receiver: %s\n", transferOutEvent.CosmosReceiver)
			fmt.Printf("Tokens: %s\n", transferOutEvent.Token.String())

			receiverAddr, err := sdk.AccAddressFromBech32(transferOutEvent.CosmosReceiver[:])
			if err != nil {
				return err
			}
			msg := types.MsgCreateEthereumClaims{
				EthereumChainID:       ethereumChainID.String(),
				BridgeContractAddress: types.NewEthereumAddress(bridgeContractAddress),
				Orchestrator:          cosmosAddr,
				Claims: []types.EthereumClaim{types.EthereumBridgeDepositClaim{
					Nonce: types.NewUInt64Nonce(transferOutEvent.DepositNonce.Uint64()),
					ERC20Token: types.ERC20Token{
						Amount:               transferOutEvent.Token.Uint64(),
						Symbol:               transferOutEvent.Symbol,
						TokenContractAddress: transferOutEvent.ERC20ContractAddress,
					},
					EthereumSender: types.EthereumAddress{},
					CosmosReceiver: receiverAddr,
				}},
			}
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			if err := utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg}); err != nil {
				return err
			}

		case bridgeContractLogWithdrawalBatch:
			fmt.Printf("[Bridge] Log Name: withdrawal batch processed\n")
			var batch BridgeContractWithdrawalBatch
			if err := bridgeContractAbi.Unpack(&batch, "WithdrawalBatchEvent", l.Data); err != nil {
				return err
			}
			fmt.Printf("nonce: %d", batch.Nonce)

			msg := types.MsgCreateEthereumClaims{
				EthereumChainID:       ethereumChainID.String(),
				BridgeContractAddress: types.NewEthereumAddress(bridgeContractAddress),
				Orchestrator:          cosmosAddr,
				Claims: []types.EthereumClaim{types.EthereumBridgeWithdrawalBatchClaim{
					Nonce: types.NewUInt64Nonce(batch.Nonce.Uint64()),
				}},
			}
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			if err := utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg}); err != nil {
				return err
			}

		case erc20LogTransferSigHash:
			fmt.Printf("[ERC20] Log Name: Transfer: %X\n", l.Data)

			var transferEvent ERC20LogTransfer
			if err := erc20Abi.Unpack(&transferEvent, "Transfer", l.Data); err != nil {
				return err
			}

			transferEvent.From = common.HexToAddress(l.Topics[1].Hex())
			transferEvent.To = common.HexToAddress(l.Topics[2].Hex())

			fmt.Printf("From: %s\n", transferEvent.From.Hex())
			fmt.Printf("To: %s\n", transferEvent.To.Hex())
			fmt.Printf("Tokens: %s\n", transferEvent.Token.String())

		case erc20LogApprovalSigHash:
			fmt.Printf("[ERC20]  Log Name: Approval\n")

			var approvalEvent ERC20LogApproval

			if err := erc20Abi.Unpack(&approvalEvent, "Approval", l.Data); err != nil {
				return err
			}
			approvalEvent.TokenOwner = common.HexToAddress(l.Topics[1].Hex())
			approvalEvent.Spender = common.HexToAddress(l.Topics[2].Hex())

			fmt.Printf("Token Owner: %s\n", approvalEvent.TokenOwner.Hex())
			fmt.Printf("Spender: %s\n", approvalEvent.Spender.Hex())
			fmt.Printf("Tokens: %s\n", approvalEvent.Token.String())

		default:
			fmt.Printf("[?]  unhandled: %X\n", l.Topics[0].Hex())
			fmt.Printf("%#v\n", l)
		}

		fmt.Printf("\n\n")
	}
	return nil
}

func loadABI(sourceFile string) (*abi.ABI, error) {
	erc20Jsonbz, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return nil, err
	}
	var tmp map[string]json.RawMessage
	err = json.Unmarshal(erc20Jsonbz, &tmp)
	if err != nil {
		return nil, err
	}
	contractAbi, err := abi.JSON(bytes.NewReader(tmp["abi"]))
	return &contractAbi, err
}

func CmdUnsafeETHBalance() *cobra.Command {
	return &cobra.Command{
		Use:   "eth-balance [erc20_contract_address] [eth_token_owner_address]",
		Short: "Print balance for the address on the Ethereum chain",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			erc20ContractAddr := types.NewEthereumAddress(args[0])
			if erc20ContractAddr.IsEmpty() {
				return errors.New("invalid contract address")
			}
			tokenOwnerAddr := types.NewEthereumAddress(args[1])
			if tokenOwnerAddr.IsEmpty() {
				return errors.New("invalid address")
			}

			client, err := ethclient.Dial(EthProvider)
			if err != nil {
				panic(err)
			}
			defer client.Close()
			fmt.Println("Started Ethereum connection with provider:", EthProvider)

			var result *big.Int
			if err := queryERC20Contract(ethCommon.Address(erc20ContractAddr), client, &result, "balanceOf", ethCommon.Address(tokenOwnerAddr)); err != nil {
				return err
			}
			var symbol string
			if err := queryERC20Contract(ethCommon.Address(erc20ContractAddr), client, &symbol, "symbol"); err != nil {
				return err
			}
			fmt.Printf("Balance: %s %s\n", result.String(), symbol)
			return nil
		},
	}
}

func queryERC20Contract(contractAddr common.Address, client *ethclient.Client, result interface{}, method string, mData ...interface{}) error {
	contractAbi, err := loadABI("../solidity/artifacts/ERC20.json")
	if err != nil {
		return err
	}
	instance := bind.NewBoundContract(contractAddr, *contractAbi, client, client, nil)
	return instance.Call(nil, &result, method, mData...)
}
