package app

import (
	"fmt"
	"math/big"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	// "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	evmtypes "github.com/confio/tgrade/x/ewasm/types"

	"github.com/ethereum/go-ethereum/common"
)

// EwasmSigVerificationDecorator validates an ethereum signatures
type EwasmSigVerificationDecorator struct {
	ak              AccountKeeper
	signModeHandler authsigning.SignModeHandler
	ewasmKeeper     EwasmKeeper
}

// NewEwasmSigVerificationDecorator creates a new EwasmSigVerificationDecorator
func NewEwasmSigVerificationDecorator(ak AccountKeeper, signModeHandler authsigning.SignModeHandler, ek EwasmKeeper) EwasmSigVerificationDecorator {
	return EwasmSigVerificationDecorator{
		ak:              ak,
		signModeHandler: signModeHandler,
		ewasmKeeper:     ek,
	}
}

// AnteHandle validates checks that the registered chain id is the same as the one on the message, and
// that the signer address matches the one defined on the message.
// It's not skipped for RecheckTx, because it set `From` address which is critical from other ante handler to work.
// Failure in RecheckTx will prevent tx to be included into block, especially when CheckTx succeed, in which case user
// won't see the error message.
func (esvd EwasmSigVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	chainID := esvd.ewasmKeeper.ChainID()
	fmt.Println("-EwasmSigVerificationDecorator-eth chainID", chainID)

	params := esvd.ewasmKeeper.GetParams(ctx)

	// ethCfg := params.ChainConfig.EthereumConfig(chainID)
	// blockNum := big.NewInt(ctx.BlockHeight())
	// signer := ethtypes.MakeSigner(ethCfg, blockNum)

	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
		if !ok {
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "invalid message type %T, expected %T", msg, (*evmtypes.MsgEthereumTx)(nil))
		}
		fmt.Println("-EwasmSigVerificationDecorator msgEthTx.From", msgEthTx.From)

		ethTx := msgEthTx.AsTransaction()
		if !params.AllowUnprotectedTxs && !ethTx.Protected() {
			return ctx, sdkerrors.Wrapf(
				sdkerrors.ErrNotSupported,
				"rejected unprotected Ethereum txs. Please EIP155 sign your transaction to protect it against replay-attacks")
		}

		fmt.Println("-EwasmSigVerificationDecorator-eth ethTx.To", ethTx.To())

		// sender, err := signer.Sender(ethTx)
		// if err != nil {
		// 	return ctx, sdkerrors.Wrapf(
		// 		sdkerrors.ErrorInvalidSigner,
		// 		"couldn't retrieve sender address from the ethereum transaction: %s",
		// 		err.Error(),
		// 	)
		// }

		// set up the sender to the transaction field if not already
		// msgEthTx.From = sender.Hex()

		fmt.Println("-EwasmSigVerificationDecorator msgEthTx.From(2)", msgEthTx.From)

		from := sdk.AccAddress(common.HexToAddress(msgEthTx.From[2:]).Bytes())
		fmt.Println("-EwasmSigVerificationDecorator from", from, from.String())

		acc, err := authante.GetSignerAcc(ctx, esvd.ak, from)
		if err != nil {
			return ctx, err
		}

		// retrieve pubkey
		pubKey := acc.GetPubKey()
		if !simulate && pubKey == nil {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidPubKey, "pubkey on account is not set")
		}
		fmt.Println("-EwasmSigVerificationDecorator pubKey", pubKey)

		// // Check account sequence number.
		// if sig.Sequence != acc.GetSequence() {
		// 	return ctx, sdkerrors.Wrapf(
		// 		sdkerrors.ErrWrongSequence,
		// 		"account sequence mismatch, expected %d, got %d", acc.GetSequence(), sig.Sequence,
		// 	)
		// }

		// retrieve signer data
		genesis := ctx.BlockHeight() == 0
		chainID := ctx.ChainID()
		var accNum uint64
		if !genesis {
			accNum = acc.GetAccountNumber()
		}
		signerData := authsigning.SignerData{
			ChainID:       chainID,
			AccountNumber: accNum,
			Sequence:      acc.GetSequence(),
		}
		fmt.Println("-EwasmSigVerificationDecorator signerData", signerData)
		// signatureData := &signing.SingleSignatureData{
		// 	// TODO fix SignMode
		// 	SignMode: esvd.signModeHandler.DefaultMode(),
		// 	Signature: ethTx.RawSignatureValues(),
		// }

		// err = authsigning.VerifySignature(pubKey, signerData, signatureData, esvd.signModeHandler, tx)
		// if err != nil {
		// 	var errMsg string
		// 	if authante.OnlyLegacyAminoSigners(ethTx.Data) {
		// 		// If all signers are using SIGN_MODE_LEGACY_AMINO, we rely on VerifySignature to check account sequence number,
		// 		// and therefore communicate sequence number as a potential cause of error.
		// 		errMsg = fmt.Sprintf("signature verification failed; please verify account number (%d), sequence (%d) and chain-id (%s)", accNum, acc.GetSequence(), chainID)
		// 	} else {
		// 		errMsg = fmt.Sprintf("signature verification failed; please verify account number (%d) and chain-id (%s)", accNum, chainID)
		// 	}
		// 	return ctx, sdkerrors.Wrap(sdkerrors.ErrUnauthorized, errMsg)

		// }
	}

	return next(ctx, tx, simulate)
}

// EthEmitEventDecorator emit events in ante handler in case of tx execution failed (out of block gas limit).
type EthEmitEventDecorator struct {
	ewasmKeeper EwasmKeeper
}

// NewEthEmitEventDecorator creates a new EthEmitEventDecorator
func NewEthEmitEventDecorator(ewasmKeeper EwasmKeeper) EthEmitEventDecorator {
	return EthEmitEventDecorator{ewasmKeeper}
}

// AnteHandle emits some basic events for the eth messages
func (eeed EthEmitEventDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	// After eth tx passed ante handler, the fee is deducted and nonce increased, it shouldn't be ignored by json-rpc,
	// we need to emit some basic events at the very end of ante handler to be indexed by tendermint.
	txIndex := eeed.ewasmKeeper.GetTxIndexTransient(ctx)
	for i, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
		if !ok {
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "invalid message type %T, expected %T", msg, (*evmtypes.MsgEthereumTx)(nil))
		}

		// emit ethereum tx hash as event, should be indexed by tm tx indexer for query purpose.
		// it's emitted in ante handler so we can query failed transaction (out of block gas limit).
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			evmtypes.EventTypeEthereumTx,
			sdk.NewAttribute(evmtypes.AttributeKeyEthereumTxHash, msgEthTx.Hash),
			sdk.NewAttribute(evmtypes.AttributeKeyTxIndex, strconv.FormatUint(txIndex+uint64(i), 10)),
		))
	}

	return next(ctx, tx, simulate)
}

// EwasmKeeper defines the expected keeper interface used on the Eth AnteHandler
type EwasmKeeper interface {
	ChainID() *big.Int
	GetParams(ctx sdk.Context) evmtypes.Params
	// DeductTxCostsFromUserBalance(
	// 	ctx sdk.Context, msgEthTx evmtypes.MsgEthereumTx, txData evmtypes.TxData, denom string, homestead, istanbul, london bool,
	// ) (sdk.Coins, error)
	// GetBaseFee(ctx sdk.Context, ethCfg *params.ChainConfig) *big.Int
	// GetBalance(ctx sdk.Context, addr common.Address) *big.Int
	// ResetTransientGasUsed(ctx sdk.Context)
	GetTxIndexTransient(ctx sdk.Context) uint64
}

// AccountKeeper defines the contract needed for AccountKeeper related APIs.
// Interface provides support to use non-sdk AccountKeeper for AnteHandler's decorators.
type AccountKeeper interface {
	GetParams(ctx sdk.Context) (params authtypes.Params)
	GetAccount(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI
	SetAccount(ctx sdk.Context, acc authtypes.AccountI)
	GetModuleAddress(moduleName string) sdk.AccAddress
}
