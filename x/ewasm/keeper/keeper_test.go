package keeper_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/rand"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	db "github.com/tendermint/tm-db"

	"github.com/CosmWasm/wasmd/x/wasm"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	"github.com/confio/tgrade/x/poe"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	"github.com/confio/tgrade/x/poe/types"
	poetypes "github.com/confio/tgrade/x/poe/types"
	twasmtypes "github.com/confio/tgrade/x/twasm/types"

	"github.com/confio/tgrade/app"
)

type KeeperTestSuite struct {
	suite.Suite

	ctx sdk.Context

	app *app.TgradeApp
	h   *app.TestSupport
	// queryClient types.QueryClient
	// signer      keyring.Signer
	consAddress sdk.ConsAddress
	// validator   stakingtypes.Validator
	denom     string
	faucet    *wasmkeeper.TestFaucet
	deliverTx func(tx abci.RequestDeliverTx) abci.ResponseDeliverTx
}

var s *KeeperTestSuite

func TestKeeperTestSuite(t *testing.T) {
	s = new(KeeperTestSuite)
	suite.Run(t, s)
}

func (suite *KeeperTestSuite) SetupTest() {
	// suite.app = app.Setup(false)
	suite.SetupApp()
}

func (suite *KeeperTestSuite) SetupApp() {
	t := suite.T()

	suite.denom = "utgd"
	// cfg := sdk.GetConfig()
	// cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	// cfg.SetBech32PrefixForValidator(app.Bech32PrefixValAddr, app.Bech32PrefixValPub)
	// cfg.SetBech32PrefixForConsensusNode(app.Bech32PrefixConsAddr, app.Bech32PrefixConsPub)
	// cfg.SetAddressVerifier(wasmtypes.VerifyAddressLen())

	chainId := "testing-5000-1"
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

	params := suite.app.EwasmKeeper.GetParams(suite.ctx)
	params.EnableEwasm = true
	suite.app.EwasmKeeper.SetParams(suite.ctx, params)

	encodingConfig := app.MakeEncodingConfig()

	suite.deliverTx = UnAuthorizedDeliverTXFn(t, suite.ctx, suite.app.EwasmKeeper.PoeKeeper, suite.app.EwasmKeeper.TwasmKeeper.GetContractKeeper(), encodingConfig.TxConfig.TxDecoder())

	suite.faucet = wasmkeeper.NewTestFaucet(t, suite.ctx, suite.app.EwasmKeeper.BankKeeper, twasmtypes.ModuleName, sdk.NewCoin(suite.denom, sdk.NewInt(100_000_000_000)))
}

func SetupWithSingleValidatorGenTX(t *testing.T, genesisState app.GenesisState) {
	// a validator needs:
	// - signed genTX
	// - account object
	// - enough funds on the bank
	// - membership in engagement group
	marshaler := app.MakeEncodingConfig().Codec
	poeGS := poetypes.GetGenesisStateFromAppState(marshaler, genesisState)
	if poeGS.GetSeedContracts() == nil {
		panic("not in seed mode")
	}

	bootstrapAccountAddr := sdk.AccAddress(rand.Bytes(address.Len))
	myGenTx, myAddr, _ := poetypes.RandomGenTX(t, 100)
	var authGenState authtypes.GenesisState
	marshaler.MustUnmarshalJSON(genesisState[authtypes.ModuleName], &authGenState)
	genAccounts := []authtypes.GenesisAccount{
		authtypes.NewBaseAccount(myAddr, nil, 0, 0),
		authtypes.NewBaseAccount(bootstrapAccountAddr, nil, 0, 0),
	}
	accounts, err := authtypes.PackAccounts(genAccounts)
	require.NoError(t, err)
	authGenState.Accounts = accounts
	genesisState[authtypes.ModuleName] = marshaler.MustMarshalJSON(&authGenState)

	var bankGenState banktypes.GenesisState
	marshaler.MustUnmarshalJSON(genesisState[banktypes.ModuleName], &bankGenState)

	coins := sdk.Coins{sdk.NewCoin(poetypes.DefaultBondDenom, sdk.NewInt(10000000000))}
	bankGenState.Balances = append(bankGenState.Balances, banktypes.Balance{Address: myAddr.String(), Coins: coins})
	bankGenState.Supply = bankGenState.Supply.Add(coins...)
	bankGenState.Balances = append(bankGenState.Balances, banktypes.Balance{Address: bootstrapAccountAddr.String(), Coins: coins})
	bankGenState.Supply = bankGenState.Supply.Add(coins...)

	genAddrAndUpdateBalance := func(numAddr int, balance sdk.Coins) []string {
		genAddr := make([]string, numAddr)
		for i := 0; i < numAddr; i++ {
			addr := poetypes.RandomAccAddress().String()
			bankGenState.Balances = append(bankGenState.Balances, banktypes.Balance{Address: addr, Coins: balance})
			genAddr[i] = addr
			bankGenState.Supply = bankGenState.Supply.Add(balance...)
		}
		return genAddr
	}
	// add 3 oc members
	ocMembers := genAddrAndUpdateBalance(3, coins)

	// add 2 ap members
	apMembers := genAddrAndUpdateBalance(2, coins)

	genesisState[banktypes.ModuleName] = marshaler.MustMarshalJSON(&bankGenState)

	// add system admin to not fail poe on validation
	poeGS.GetSeedContracts().BondDenom = poetypes.DefaultBondDenom
	poeGS.GetSeedContracts().GenTxs = []json.RawMessage{myGenTx}
	poeGS.GetSeedContracts().Engagement = []poetypes.TG4Member{{Address: myAddr.String(), Points: 10}}
	poeGS.GetSeedContracts().BootstrapAccountAddress = bootstrapAccountAddr.String()
	poeGS.GetSeedContracts().OversightCommunityMembers = ocMembers
	poeGS.GetSeedContracts().ArbiterPoolMembers = apMembers
	genesisState = poetypes.SetGenesisStateInAppState(marshaler, genesisState, poeGS)
}

// Commit commits and starts a new block with an updated context.
func (suite *KeeperTestSuite) Commit() {
	suite.CommitAfter(time.Second * 0)
}

// Commit commits a block at a given time.
func (suite *KeeperTestSuite) CommitAfter(t time.Duration) {
	header := suite.ctx.BlockHeader()
	suite.app.EndBlock(abci.RequestEndBlock{Height: header.Height})
	_ = suite.app.Commit()

	header.Height += 1
	header.Time = header.Time.Add(t)
	suite.app.BeginBlock(abci.RequestBeginBlock{
		Header: header,
	})

	// update ctx
	suite.ctx = suite.app.BaseApp.NewContext(false, header)
}

var DEFAULT_GAS_PRICE = "0.05utgd"
var DEFAULT_GAS_LIMIT = uint64(5_000_000)

func (s *KeeperTestSuite) prepareCosmosTx(account simulation.Account, msgs []sdk.Msg, gasLimit *uint64, gasPrice *string) []byte {
	encodingConfig := app.MakeEncodingConfig()
	txBuilder := encodingConfig.TxConfig.NewTxBuilder()
	var parsedGasPrices sdk.DecCoins
	var err error

	if gasLimit != nil {
		txBuilder.SetGasLimit(*gasLimit)
	} else {
		txBuilder.SetGasLimit(DEFAULT_GAS_LIMIT)
	}

	if gasPrice != nil {
		parsedGasPrices, err = sdk.ParseDecCoins(*gasPrice)
	} else {
		parsedGasPrices, err = sdk.ParseDecCoins(DEFAULT_GAS_PRICE)
	}
	s.Require().NoError(err)
	feeAmount := parsedGasPrices.AmountOf("utgd").MulInt64(int64(DEFAULT_GAS_LIMIT)).RoundInt()

	fees := &sdk.Coins{{Denom: s.denom, Amount: feeAmount}}
	txBuilder.SetFeeAmount(*fees)
	err = txBuilder.SetMsgs(msgs...)
	s.Require().NoError(err)

	seq, err := s.app.EwasmKeeper.AccountKeeper.GetSequence(s.ctx, account.Address)
	s.Require().NoError(err)
	fmt.Println("----sender seq--", seq, account.Address.String())

	// First round: we gather all the signer infos. We use the "set empty
	// signature" hack to do that.
	sigV2 := signing.SignatureV2{
		PubKey: account.PubKey,
		Data: &signing.SingleSignatureData{
			SignMode:  encodingConfig.TxConfig.SignModeHandler().DefaultMode(),
			Signature: nil,
		},
		Sequence: seq,
	}

	err = txBuilder.SetSignatures(sigV2)
	s.Require().NoError(err)

	// Second round: all signer infos are set, so each signer can sign.
	accNumber := s.app.EwasmKeeper.AccountKeeper.GetAccount(s.ctx, account.Address).GetAccountNumber()
	signerData := authsigning.SignerData{
		ChainID:       s.ctx.ChainID(),
		AccountNumber: accNumber,
		Sequence:      seq,
	}
	sigV2, err = tx.SignWithPrivKey(
		encodingConfig.TxConfig.SignModeHandler().DefaultMode(), signerData,
		txBuilder, account.PrivKey, encodingConfig.TxConfig,
		seq,
	)
	s.Require().NoError(err)

	err = txBuilder.SetSignatures(sigV2)
	s.Require().NoError(err)

	// bz are bytes to be broadcasted over the network
	bz, err := encodingConfig.TxConfig.TxEncoder()(txBuilder.GetTx())
	s.Require().NoError(err)
	return bz
}

func (s *KeeperTestSuite) DeliverTx(account simulation.Account, msgs ...sdk.Msg) abci.ResponseDeliverTx {
	bz := s.prepareCosmosTx(account, msgs, nil, nil)
	req := abci.RequestDeliverTx{Tx: bz}
	res := s.app.BaseApp.DeliverTx(req)
	return res
}

func (s *KeeperTestSuite) DeliverTxWithOpts(account simulation.Account, msg sdk.Msg, gasLimit uint64, gasPrice *string) abci.ResponseDeliverTx {
	bz := s.prepareCosmosTx(account, []sdk.Msg{msg}, &gasLimit, gasPrice)
	req := abci.RequestDeliverTx{Tx: bz}
	res := s.app.BaseApp.DeliverTx(req)
	return res
}

func (s *KeeperTestSuite) GetRandomAccount() simulation.Account {
	pk := ed25519.GenPrivKey()
	privKey := secp256k1.GenPrivKeyFromSecret(pk.GetKey().Seed())
	pubKey := privKey.PubKey()
	address := sdk.AccAddress(pubKey.Address())
	account := simulation.Account{
		PrivKey: privKey,
		PubKey:  pubKey,
		Address: address,
	}
	return account
}

// unAuthorizedDeliverTXFn applies the TX without ante handler checks for testing purpose
func UnAuthorizedDeliverTXFn(t *testing.T, ctx sdk.Context, k poekeeper.PoEKeeper, contractKeeper wasmtypes.ContractOpsKeeper, txDecoder sdk.TxDecoder) func(tx abci.RequestDeliverTx) abci.ResponseDeliverTx {
	t.Helper()
	h := poe.NewHandler(k, contractKeeper, nil)
	return func(tx abci.RequestDeliverTx) abci.ResponseDeliverTx {
		genTx, err := txDecoder(tx.GetTx())
		require.NoError(t, err)
		msgs := genTx.GetMsgs()
		require.Len(t, msgs, 1)
		msg := msgs[0].(*types.MsgCreateValidator)
		_, err = h(ctx, msg)
		require.NoError(t, err)
		return abci.ResponseDeliverTx{}
	}
}

type Attribute struct {
	Key   string
	Value string
}

type Event struct {
	Type       string
	Attributes *[]Attribute
}

type Log struct {
	MsgIndex uint64
	Events   []Event
}

func (s *KeeperTestSuite) GetFromLog(logstr string, logtype string) *[]Attribute {
	var logs []Log
	err := json.Unmarshal([]byte(logstr), &logs)
	s.Require().NoError(err)
	for _, log := range logs {
		for _, ev := range log.Events {
			if ev.Type == logtype {
				return ev.Attributes
			}
		}
	}
	return nil
}

func (s *KeeperTestSuite) GetCodeIdFromLog(logstr string) uint64 {
	attrs := s.GetFromLog(logstr, "store_code")
	if attrs == nil {
		return 0
	}
	for _, attr := range *attrs {
		if attr.Key == "code_id" {
			ui64, err := strconv.ParseUint(attr.Value, 10, 64)
			s.Require().NoError(err)
			return ui64
		}
	}
	return 0
}

func (s *KeeperTestSuite) GetContractAddressFromLog(logstr string) string {
	attrs := s.GetFromLog(logstr, "instantiate")
	s.Require().NotNil(attrs)
	for _, attr := range *attrs {
		if attr.Key == "_contract_address" {
			return attr.Value
		}
	}
	s.Require().True(false, "no contract address found in log")
	return ""
}
