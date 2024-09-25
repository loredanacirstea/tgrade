package upgrades

import (
	"encoding/json"
	"fmt"
	"math/rand"

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"
	abci "github.com/tendermint/tendermint/abci/types"

	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	upgradekeeper "github.com/cosmos/cosmos-sdk/x/upgrade/keeper"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

	"github.com/confio/tgrade/x/poe/simulation"
)

var (
	ModuleName                       = "manualupdate"
	_          module.AppModule      = AppModule{}
	_          module.AppModuleBasic = AppModuleBasic{}
)

// 0x0 -> Plan
// Done: 0x1 | byte(plan name) -> BigEndian(Block Height)
func BeginBlocker(ctx sdk.Context, uk upgradekeeper.Keeper, upgradeStoreKey sdk.StoreKey, appCodec codec.Codec) {
	fmt.Println("--upgrades BeginBlocker StoreKey--", upgradeStoreKey)
	upgradeInfo, err := uk.ReadUpgradeInfoFromDisk()
	fmt.Println("--ReadUpgradeInfoFromDisk--", err, upgradeInfo)
	if err == nil && !uk.IsSkipHeight(upgradeInfo.Height) {
		store := ctx.KVStore(upgradeStoreKey)
		// check if upgrade was applied already and skip
		height := uk.GetDoneHeight(ctx, upgradeInfo.Name)
		if height != 0 {
			return
		}
		plan := &upgradetypes.Plan{
			Name:   upgradeInfo.Name,
			Height: upgradeInfo.Height,
		}
		planbz := appCodec.MustMarshal(plan)
		store.Set(upgradetypes.PlanKey(), planbz)
	}
	fmt.Println("--upgrades BeginBlocker END--")
}

// AppModuleBasic defines the basic application module used by the genutil module.
type AppModuleBasic struct{}

// Name returns the genutil module's name.
func (AppModuleBasic) Name() string {
	return ModuleName
}

// RegisterLegacyAminoCodec registers the genutil module's types on the given LegacyAmino codec.
func (AppModuleBasic) RegisterLegacyAminoCodec(amino *codec.LegacyAmino) {}

// RegisterInterfaces registers the module's interface types
func (b AppModuleBasic) RegisterInterfaces(registry cdctypes.InterfaceRegistry) {}

// DefaultGenesis returns default genesis state as raw bytes for the genutil
// module.
func (b AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return []byte(`{}`)
}

// ValidateGenesis performs genesis state validation for the genutil module.
func (b AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, txEncodingConfig client.TxEncodingConfig, bz json.RawMessage) error {
	return nil
}

// RegisterRESTRoutes registers the REST routes for the genutil module.
func (AppModuleBasic) RegisterRESTRoutes(_ client.Context, _ *mux.Router) {}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the genutil module.
func (b AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, serveMux *runtime.ServeMux) {
}

// GetTxCmd returns no root tx command for the genutil module.
func (AppModuleBasic) GetTxCmd() *cobra.Command { return nil }

// GetQueryCmd returns no root query command for the genutil module.
func (AppModuleBasic) GetQueryCmd() *cobra.Command { return nil }

// AppModule implements an application module for the genutil module.
type AppModule struct {
	AppModuleBasic
	uk              upgradekeeper.Keeper
	upgradeStoreKey sdk.StoreKey
	appCodec        codec.Codec
}

// NewAppModule creates a new AppModule object
func NewAppModule(uk upgradekeeper.Keeper, upgradeStoreKey sdk.StoreKey, appCodec codec.Codec) AppModule {
	return AppModule{
		AppModuleBasic:  AppModuleBasic{},
		uk:              uk,
		upgradeStoreKey: upgradeStoreKey,
		appCodec:        appCodec,
	}
}

func (am AppModule) RegisterInvariants(registry sdk.InvariantRegistry) {}

func (am AppModule) Route() sdk.Route {
	return sdk.Route{}
}

func (am AppModule) QuerierRoute() string {
	return ModuleName
}

func (am AppModule) LegacyQuerierHandler(amino *codec.LegacyAmino) sdk.Querier {
	return nil
}

func (am AppModule) RegisterServices(cfg module.Configurator) {}

func (am AppModule) BeginBlock(ctx sdk.Context, block abci.RequestBeginBlock) {
	BeginBlocker(ctx, am.uk, am.upgradeStoreKey, am.appCodec)
}

func (am AppModule) EndBlock(ctx sdk.Context, block abci.RequestEndBlock) []abci.ValidatorUpdate {
	return []abci.ValidatorUpdate{}
}

// InitGenesis performs genesis initialization for the genutil module. It returns
// no validator updates.
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns the exported genesis state as raw bytes for the genutil
// module.
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	// gs := keeper.ExportGenesis(ctx, am.poeKeeper)
	// return cdc.MustMarshalJSON(gs)
	return []byte(`{}`)
}

// ConsensusVersion is a sequence number for state-breaking change of the
// module. It should be incremented on each consensus-breaking change
// introduced by the module. To avoid wrong/empty versions, the initial version
// should be set to 1.
func (am AppModule) ConsensusVersion() uint64 {
	return 1
}

// GenerateGenesisState creates a randomized GenState of the PoE module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	simulation.RandomizedGenState(simState)
}

// ProposalContents doesn't return any content functions for governance proposals.
func (AppModule) ProposalContents(simState module.SimulationState) []simtypes.WeightedProposalContent {
	return nil
}

// RandomizedParams creates randomized PoE param changes for the simulator.
func (AppModule) RandomizedParams(r *rand.Rand) []simtypes.ParamChange {
	return nil
}

// RegisterStoreDecoder registers a decoder for PoE module's types
func (am AppModule) RegisterStoreDecoder(sdr sdk.StoreDecoderRegistry) {
}

// WeightedOperations returns the all the PoE module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	return []simtypes.WeightedOperation{}
}
