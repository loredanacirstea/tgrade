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

	"github.com/confio/tgrade/x/ewasm/types"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	twasmkeeper "github.com/confio/tgrade/x/twasm/keeper"
)

type Keeper struct {
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
	ps paramtypes.Subspace,
	registry cdctypes.InterfaceRegistry,
	bankKeeper bankkeeper.Keeper,
	accountKeeper authkeeper.AccountKeeper,
	poeKeeper poekeeper.PoEKeeper,
	twasmKeeper twasmkeeper.Keeper,
) Keeper {

	// set KeyTable if it has not already been set
	if !ps.HasKeyTable() {
		ps = ps.WithKeyTable(types.ParamKeyTable())
	}

	return Keeper{
		Cdc:        cdc,
		storeKey:   storeKey,
		paramstore: ps,

		AccountKeeper:     accountKeeper,
		BankKeeper:        bankKeeper,
		PoeKeeper:         poeKeeper,
		TwasmKeeper:       twasmKeeper,
		interfaceRegistry: registry,
	}
}

// Logger returns the application logger, scoped to the associated module
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s-%s", host.ModuleName, types.ModuleName))
}

func (k Keeper) InterfaceRegistry(ctx sdk.Context) cdctypes.InterfaceRegistry {
	return k.interfaceRegistry
}
