package keeper

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	"github.com/tendermint/tendermint/libs/log"

	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	host "github.com/cosmos/ibc-go/v4/modules/core/24-host"

	ethermintkeeper "github.com/evmos/ethermint/x/evm/keeper"
	etherminttypes "github.com/evmos/ethermint/x/evm/types"

	"github.com/confio/tgrade/x/ewasm/types"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	twasmkeeper "github.com/confio/tgrade/x/twasm/keeper"
)

type Keeper struct {
	ethermintKeeper   ethermintkeeper.Keeper
	Cdc               codec.Codec
	storeKey          storetypes.StoreKey
	paramstore        paramtypes.Subspace
	AccountKeeper     authkeeper.AccountKeeper
	BankKeeper        bankkeeper.Keeper
	PoeKeeper         poekeeper.PoEKeeper
	TwasmKeeper       twasmkeeper.Keeper
	interfaceRegistry cdctypes.InterfaceRegistry
}

// TODO remove unused
func NewKeeper(
	cdc codec.Codec,
	storeKey storetypes.StoreKey,
	transientKey storetypes.StoreKey,
	ps paramtypes.Subspace,
	registry cdctypes.InterfaceRegistry,
	accountKeeper authkeeper.AccountKeeper,
	bankKeeper bankkeeper.Keeper,
	stakingKeeper etherminttypes.StakingKeeper,
	// fetch EIP1559 base fee and parameters
	feeMarketKeeper etherminttypes.FeeMarketKeeper,
	// chain ID number obtained from the context's chain id
	// eip155ChainID *big.Int,
	// Tracer used to collect execution traces from the EVM transaction execution
	tracer string,
	// EVM Hooks for tx post-processing
	// hooks etherminttypes.EvmHooks,

	poeKeeper poekeeper.PoEKeeper,
	twasmKeeper twasmkeeper.Keeper,
) Keeper {

	// set KeyTable if it has not already been set
	if !ps.HasKeyTable() {
		ps = ps.WithKeyTable(types.ParamKeyTable())
	}

	ethermintKeeper := ethermintkeeper.NewKeeper(cdc, storeKey, transientKey, ps, accountKeeper, bankKeeper, stakingKeeper, feeMarketKeeper, tracer)

	return Keeper{
		Cdc:               cdc,
		storeKey:          storeKey,
		paramstore:        ps,
		AccountKeeper:     accountKeeper,
		BankKeeper:        bankKeeper,
		PoeKeeper:         poeKeeper,
		TwasmKeeper:       twasmKeeper,
		interfaceRegistry: registry,
		ethermintKeeper:   *ethermintKeeper,
	}
}

// Logger returns the application logger, scoped to the associated module
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s-%s", host.ModuleName, types.ModuleName))
}

func (k Keeper) InterfaceRegistry() cdctypes.InterfaceRegistry {
	return k.interfaceRegistry
}

func (k Keeper) EthermintKeeper() ethermintkeeper.Keeper {
	return k.ethermintKeeper
}
