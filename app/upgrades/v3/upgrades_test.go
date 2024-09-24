package v3_test

import (
	"encoding/json"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/confio/tgrade/app"
	v3 "github.com/confio/tgrade/app/upgrades/v3"
	poetesting "github.com/confio/tgrade/testing"
	"github.com/confio/tgrade/x/poe/contract"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	"github.com/confio/tgrade/x/twasm"
)

func TestCreateUpgradeHandler(t *testing.T) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	ctx, keepers, _ := poetesting.SetupPoEContracts(t)

	ak := keepers.AccountKeeper
	pk := keepers.PoEKeeper
	twasmk := keepers.TWasmKeeper
	// poeserv := poekeeper.NewMsgServerImpl(pk, twasmk.GetContractKeeper(), twasmk)
	// when

	handler := v3.CreateUpgradeHandler(&module.Manager{}, module.NewConfigurator(nil, nil, nil), ak, pk, twasmk)
	_, err := handler(ctx, upgradetypes.Plan{}, module.VersionMap{})
	// then
	require.NoError(t, err)

	// TgradeSudoMsg EndBlock
	upds := twasm.EndBlocker(ctx, twasmk)
	fmt.Println("-upds--", upds)

	whitelist := v3.WhitelistedValidators()

	validators, _, err := pk.ValsetContract(ctx).ListValidators(ctx, nil)
	// fmt.Println("-validators final-", err, validators)
	require.NoError(t, err)

	for _, val := range validators {
		fmt.Println("-validator final-", val.Status.String(), val.Jailed, val.IsUnbonded(), val.IsUnbonding(), val.BondedTokens())
	}

	pk.ValsetContract(ctx).IterateActiveValidators(ctx, func(val contract.ValidatorInfo) bool {
		fmt.Println("-val-", val.Operator, val.Power, val)
		return false
	}, nil)

	// TODO expect stakingtypes.Unbonded

	for _, a := range whitelist {
		// vestingAccount, ok := ak.GetAccount(ctx, sdk.MustAccAddressFromBech32(a)).(*vestingtypes.ContinuousVestingAccount)
		// assert.True(t, ok, "vesting account")
		// assert.Equal(t, int64(1688220000), vestingAccount.GetEndTime())
		fmt.Println("---a---", a)
	}
}

func TestCreateUpgradeHandler1(t *testing.T) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	tgrade := app.Setup(true)
	tgrade.InitChain(
		abci.RequestInitChain{
			Validators:      []abci.ValidatorUpdate{},
			ConsensusParams: app.DefaultConsensusParams,
			AppStateBytes:   []byte(`{}`),
		},
	)

	h := app.NewTestSupport(t, tgrade)
	ak := h.AccountKeeper()
	pk := h.PoeKeeper()
	twasmk := h.TwasmKeeper()
	poeserv := poekeeper.NewMsgServerImpl(pk, twasmk.GetContractKeeper(), twasmk)
	fmt.Println("--poeserv--", poeserv)

	var raws []json.RawMessage
	require.NoError(t, json.Unmarshal(validatorState, &raws))
	ctx := tgrade.NewContext(false, tmproto.Header{})

	for _, raw := range raws {
		var val stakingtypes.Validator
		// require.NoError(t, h.AppCodec().UnmarshalInterfaceJSON(raw, &val))
		require.NoError(t, h.AppCodec().UnmarshalJSON(raw, &val))
		// poeserv.CreateValidator()
		// ak.SetAccount(ctx, acc)
		// require.NotNil(t, ak.GetAccount(ctx, acc.GetAddress()))
	}
	// when
	handler := v3.CreateUpgradeHandler(&module.Manager{}, module.NewConfigurator(nil, nil, nil), ak, pk, twasmk)
	_, err := handler(ctx, upgradetypes.Plan{}, module.VersionMap{})
	// then
	require.NoError(t, err)
	for _, a := range v3.WhitelistedValidators() {
		// vestingAccount, ok := ak.GetAccount(ctx, sdk.MustAccAddressFromBech32(a)).(*vestingtypes.ContinuousVestingAccount)
		// assert.True(t, ok, "vesting account")
		// assert.Equal(t, int64(1688220000), vestingAccount.GetEndTime())
		fmt.Println("---a---", a)
	}
}

var validatorState = []byte(`[{
	"operator_address": "tgrade102c8nrsw5wlezdkj9m6rvmx8rrlwf5n0t2yatd",
	"consensus_pubkey": {
	"@type": "/cosmos.crypto.ed25519.PubKey",
	"key": "SX0an7ksXLW852sWk3dZAT4MrZGfFqOfVhTM15IlMQ8="
	},
	"jailed": false,
	"status": "BOND_STATUS_BONDED",
	"tokens": "0",
	"delegator_shares": "1.000000000000000000",
	"description": {
	"moniker": "Cosmic Validator",
	"identity": "FF4B91B50B71CEDA",
	"website": "https://cosmicvalidator.com",
	"security_contact": "",
	"details": "OG #Cosmos validator and supporting since 2017⚛️. 📽Check our bi-weekly Cosmos ecosystem news videos: https://www.youtube.com/channel/UCX7kHUiacI6ycHF8Wd8mGmw"
	},
	"unbonding_height": "0",
	"unbonding_time": "0001-01-01T00:00:00Z",
	"commission": {
	"commission_rates": {
		"rate": "0.000000000000000000",
		"max_rate": "0.000000000000000000",
		"max_change_rate": "0.000000000000000000"
	},
	"update_time": "0001-01-01T00:00:00Z"
	},
	"min_self_delegation": "0"
}]`)
