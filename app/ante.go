package app

import (
	"fmt"
	"runtime/debug"

	tmlog "github.com/tendermint/tendermint/libs/log"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	ibcante "github.com/cosmos/ibc-go/v4/modules/core/ante"
	ibcCoreKeeper "github.com/cosmos/ibc-go/v4/modules/core/keeper"

	"github.com/confio/tgrade/x/globalfee"
	"github.com/confio/tgrade/x/poe"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	poetypes "github.com/confio/tgrade/x/poe/types"
)

// HandlerOptions extend the SDK's AnteHandler options by requiring the IBC
// channel keeper and additional wasm + tgrade types
type HandlerOptions struct {
	AccountKeeper   ante.AccountKeeper
	BankKeeper      poetypes.BankKeeper
	FeegrantKeeper  ante.FeegrantKeeper
	EwasmKeeper     EwasmKeeper
	SignModeHandler authsigning.SignModeHandler
	SigGasConsumer  func(meter sdk.GasMeter, sig signing.SignatureV2, params authtypes.Params) error

	IBCCoreKeeper     *ibcCoreKeeper.Keeper
	WasmConfig        *wasmtypes.WasmConfig
	TXCounterStoreKey sdk.StoreKey
	GlobalFeeSubspace paramtypes.Subspace
	ContractSource    poekeeper.ContractSource
}

func (options HandlerOptions) validate() error {
	if options.AccountKeeper == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "account keeper is required for AnteHandler")
	}
	if options.BankKeeper == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "bank keeper is required for AnteHandler")
	}
	if options.SignModeHandler == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "sign mode handler is required for ante builder")
	}
	if options.FeegrantKeeper == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "feegrant keeper is required for ante builder")
	}
	if options.WasmConfig == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "wasm config is required for ante builder")
	}
	if options.TXCounterStoreKey == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "tx counter key is required for ante builder")
	}
	if options.GlobalFeeSubspace.Name() == "" {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "param store is required for ante builder")
	}
	if options.ContractSource == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "contract source is required for ante builder")
	}
	if options.IBCCoreKeeper == nil {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "ibc core keeper is required for ante builder")
	}
	return nil
}

func newEwasmAnteHandler(options HandlerOptions) sdk.AnteHandler {
	sigGasConsumer := options.SigGasConsumer
	if sigGasConsumer == nil {
		sigGasConsumer = ante.DefaultSigVerificationGasConsumer
	}

	return sdk.ChainAnteDecorators(
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreKey),
		ante.NewMempoolFeeDecorator(),
		globalfee.NewGlobalMinimumChainFeeDecorator(options.GlobalFeeSubspace), // after local min fee check
		// ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		// poe.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ContractSource),

		// SetPubKeyDecorator must be called before all signature verification decorators
		// ante.NewSetPubKeyDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, sigGasConsumer),
		// ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		NewEwasmSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler, options.EwasmKeeper),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewAnteDecorator(options.IBCCoreKeeper),
	)
}

func newCosmosAnteHandler(options HandlerOptions) sdk.AnteHandler {
	sigGasConsumer := options.SigGasConsumer
	if sigGasConsumer == nil {
		sigGasConsumer = ante.DefaultSigVerificationGasConsumer
	}

	return sdk.ChainAnteDecorators(
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreKey),
		ante.NewRejectExtensionOptionsDecorator(),
		ante.NewMempoolFeeDecorator(),
		globalfee.NewGlobalMinimumChainFeeDecorator(options.GlobalFeeSubspace), // after local min fee check
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		poe.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ContractSource),

		// SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewSetPubKeyDecorator(options.AccountKeeper),
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, sigGasConsumer),
		ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewAnteDecorator(options.IBCCoreKeeper),
	)
}

// NewAnteHandler constructor that setup the full ante handler chain for the application
func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	return func(
		ctx sdk.Context, tx sdk.Tx, sim bool,
	) (newCtx sdk.Context, err error) {
		var anteHandler sdk.AnteHandler

		defer Recover(ctx.Logger(), &err)

		txWithExtensions, ok := tx.(authante.HasExtensionOptionsTx)
		if ok {
			opts := txWithExtensions.GetExtensionOptions()
			if len(opts) > 0 {
				switch typeURL := opts[0].GetTypeUrl(); typeURL {
				case "/confio.ewasm.v1beta1.ExtensionOptionsEthereumTx":
					// handle as *evmtypes.MsgEthereumTx
					anteHandler = newEwasmAnteHandler(options)
				default:
					return ctx, sdkerrors.Wrapf(
						sdkerrors.ErrUnknownExtensionOptions,
						"rejecting tx with unsupported extension option: %s", typeURL,
					)
				}

				return anteHandler(ctx, tx, sim)
			}
		}

		// handle as totally normal Cosmos SDK tx
		switch tx.(type) {
		case sdk.Tx:
			anteHandler = newCosmosAnteHandler(options)
		default:
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "invalid transaction type: %T", tx)
		}

		return anteHandler(ctx, tx, sim)
	}, nil
}

func Recover(logger tmlog.Logger, err *error) {
	if r := recover(); r != nil {
		*err = sdkerrors.Wrapf(sdkerrors.ErrPanic, "%v", r)

		if e, ok := r.(error); ok {
			logger.Error(
				"ante handler panicked",
				"error", e,
				"stack trace", string(debug.Stack()),
			)
		} else {
			logger.Error(
				"ante handler panicked",
				"recover", fmt.Sprintf("%v", r),
			)
		}
	}
}
