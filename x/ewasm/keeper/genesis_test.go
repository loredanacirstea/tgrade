package keeper_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CosmWasm/wasmd/x/wasm"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	db "github.com/tendermint/tm-db"

	"github.com/confio/tgrade/app"
	"github.com/confio/tgrade/x/ewasm/types"
)

type GenesisTestSuite struct {
	suite.Suite

	ctx sdk.Context

	app     *app.TgradeApp
	genesis types.GenesisState
}

func (suite *GenesisTestSuite) SetupTest() {
	t := suite.T()
	chainId := "testing-1"
	db := db.NewMemDB()
	var emptyWasmOpts []wasm.Option
	gapp := app.NewTgradeApp(log.NewTMLogger(log.NewSyncWriter(os.Stdout)), db, nil, true, map[int64]bool{}, app.DefaultNodeHome, 0, app.MakeEncodingConfig(), app.EmptyBaseAppOptions{}, emptyWasmOpts)
	genesisState := app.NewDefaultGenesisState()

	SetupWithSingleValidatorGenTX(t, genesisState)

	stateBytes, err := json.MarshalIndent(genesisState, "", "  ")
	require.NoError(t, err)
	// Initialize the chain
	now := time.Now().UTC()
	consensusParams := app.DefaultConsensusParams
	consensusParams.Block.MaxGas = 20_000_000
	gapp.InitChain(
		abci.RequestInitChain{
			// ChainId:         chainId,
			ConsensusParams: consensusParams,
			Time:            now,
			Validators:      []abci.ValidatorUpdate{},
			AppStateBytes:   stateBytes,
		},
	)
	gapp.Commit()
	suite.app = gapp

	now = time.Now().UTC()
	header := tmproto.Header{ChainID: chainId, Height: 2, Time: now, AppHash: []byte("myAppHash")}
	gapp.BaseApp.BeginBlock(abci.RequestBeginBlock{Header: header})

	suite.ctx = gapp.BaseApp.NewContext(false, header)

	suite.genesis = *types.DefaultGenesisState()
}

func TestGenesisTestSuite(t *testing.T) {
	suite.Run(t, new(GenesisTestSuite))
}

func (suite *GenesisTestSuite) TestEwasmInitGenesis() {
	testCases := []struct {
		name     string
		genesis  types.GenesisState
		expPanic bool
	}{
		{
			"default genesis",
			suite.genesis,
			false,
		},
		{
			"custom genesis - ewasm disabled",
			types.GenesisState{
				Params: types.Params{
					EnableEwasm: false,
				},
			},
			false,
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.name), func() {
			suite.SetupTest() // reset

			if tc.expPanic {
				suite.Require().Panics(func() {
					suite.app.EwasmKeeper.InitGenesis(suite.ctx, tc.genesis)
				})
			} else {
				suite.Require().NotPanics(func() {
					suite.app.EwasmKeeper.InitGenesis(suite.ctx, tc.genesis)
				})

				params := suite.app.EwasmKeeper.GetParams(suite.ctx)
				suite.Require().Equal(tc.genesis.Params, params)
			}
		})
	}
}

func (suite *GenesisTestSuite) TestEwasmExportGenesis() {
	suite.app.EwasmKeeper.InitGenesis(suite.ctx, suite.genesis)

	genesisExported := suite.app.EwasmKeeper.ExportGenesis(suite.ctx)
	suite.Require().Equal(genesisExported.Params, suite.genesis.Params)
}
