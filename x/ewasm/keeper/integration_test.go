package keeper_test

import (
	_ "embed"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	// wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	// twasmcontract "github.com/confio/tgrade/x/twasm/contract"
)

var (
	//go:embed contracts/opcodes.wasm
	opcodeswasm []byte
)

func (suite *KeeperTestSuite) TestWasm() {
	fmt.Println("=========================TestWasm")
	// mySenderContractAddr := twasmtypes.RandomAddress(t)
	sender := suite.GetRandomAccount()
	// receiver := suite.GetRandomAccount()
	initBalance := sdk.NewInt(1000_000_000)

	fmt.Println("----sender--", sender.PubKey.Address().String())
	fmt.Println("----sender--", sender.Address.String())

	suite.faucet.Fund(suite.ctx, sender.Address, sdk.NewCoin(suite.denom, initBalance))
	suite.Commit()

	senderBalance := suite.app.EwasmKeeper.BankKeeper.GetBalance(suite.ctx, sender.Address, suite.denom)
	fmt.Println("---senderBalance", senderBalance)

	permission := &wasmtypes.AccessConfig{
		Permission: wasmtypes.AccessTypeEverybody,
	}
	storeCodeMsg := &wasmtypes.MsgStoreCode{
		Sender:                sender.Address.String(),
		WASMByteCode:          opcodeswasm,
		InstantiatePermission: permission,
	}

	res := suite.DeliverTx(sender, storeCodeMsg)
	s.Require().True(res.IsOK(), res.GetLog())
	suite.Commit()

	codeId := suite.GetCodeIdFromLog(res.GetLog())
	fmt.Println("--TestWasm-codeId", codeId)

	instantiateMsgRaw := `{"name":"Token","symbol":"TKN","decimals":6,"initial_supply":"10000000000","mint_denom":"utgd"}`
	instantiateMsg := []byte(instantiateMsgRaw)

	instantiateCodeMsg := &wasmtypes.MsgInstantiateContract{
		Sender: sender.Address.String(),
		CodeID: codeId,
		Label:  "test",
		Msg:    instantiateMsg,
	}
	res = suite.DeliverTx(sender, instantiateCodeMsg)
	fmt.Println("---res", res.GetLog())
	s.Require().True(res.IsOK(), res.GetLog())
	suite.Commit()

	contractAddressStr := suite.GetContractAddressFromLog(res.GetLog())
	fmt.Println("---contractAddressStr", contractAddressStr)
	contractAddress := sdk.MustAccAddressFromBech32(contractAddressStr)

	querybz := []byte(`{"name":{}}`)
	queryres, err := s.app.EwasmKeeper.TwasmKeeper.QuerySmart(suite.ctx, contractAddress, querybz)
	s.Require().NoError(err)
	fmt.Println("---queryres", queryres, string(queryres))

	s.Require().True(false, "---")
}
