package keeper_test

import (
	_ "embed"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
)

var (

	//go:embed contracts/erc20cw.wasm
	erc20cw []byte

	//go:embed contracts/opcodes.wasm
	opcodeswasm []byte

	//go:embed contracts/opcodes_yul2.wasm
	opcodesyulwasm []byte

	//go:embed contracts/cwargs2.wasm
	cwargswasm []byte

	//go:embed contracts/cwoargs.wasm
	cwoargswasm []byte

	//go:embed contracts/cwoargs_print.wasm
	cwoargsprintwasm []byte

	//go:embed contracts/cwoargs3.wasm
	cwoargsprintwasm3 []byte

	//go:embed contracts/simplest.wasm
	simplest []byte
)

func (suite *KeeperTestSuite) TestEwasmTx() {
	// wasmbin := opcodeswasm
	wasmbin := opcodesyulwasm
	sender := suite.GetRandomAccount()
	initBalance := sdk.NewInt(1000_000_000)

	suite.faucet.Fund(suite.ctx, sender.Address, sdk.NewCoin(suite.denom, initBalance))
	suite.Commit()

	permission := &wasmtypes.AccessConfig{
		Permission: wasmtypes.AccessTypeEverybody,
	}
	storeCodeMsg := &wasmtypes.MsgStoreCode{
		Sender:                sender.Address.String(),
		WASMByteCode:          wasmbin,
		InstantiatePermission: permission,
	}

	res := suite.DeliverTx(sender, storeCodeMsg)
	s.Require().True(res.IsOK(), res.GetLog())
	suite.Commit()

	codeId := suite.GetCodeIdFromLog(res.GetLog())

	bytecode, err := suite.app.EwasmKeeper.TwasmKeeper.GetByteCode(suite.ctx, codeId)
	s.Require().NoError(err)
	s.Require().Equal(bytecode, wasmbin)

	instantiateMsg := []byte(`{"data": "0x1212121212444444444444"}`)
	instantiateCodeMsg := &wasmtypes.MsgInstantiateContract{
		Sender: sender.Address.String(),
		CodeID: codeId,
		Label:  "test",
		Msg:    instantiateMsg,
	}
	res = suite.DeliverTxWithOpts(sender, instantiateCodeMsg, 235690, nil) // 135690
	s.Require().True(res.IsOK(), res.GetLog())
	suite.Commit()

	contractAddress := suite.GetContractAddressFromLog(res.GetLog())

	executeMsg := []byte(`{"data": "0x0022"}`)
	executeCodeMsg := &wasmtypes.MsgExecuteContract{
		Sender:   sender.Address.String(),
		Contract: contractAddress,
		Msg:      executeMsg,
		Funds:    sdk.Coins{},
	}
	res = suite.DeliverTxWithOpts(sender, executeCodeMsg, 235690, nil) // 135690
	s.Require().True(res.IsOK(), res.GetLog())
	suite.Commit()

	contractAddressAcc, err := sdk.AccAddressFromBech32(contractAddress)
	s.Require().NoError(err)
	contractAddressCommon := common.BytesToAddress(contractAddressAcc.Bytes())
	fmt.Println("==contractAddressCommon==", contractAddressCommon)

	fmt.Println("==EwasmSigVerificationDecorator000===sender", sender.Address.String(), common.BytesToAddress(sender.Address.Bytes()).Hex())

	msgEthereumTx := s.buildEthTxSimple(sender, &contractAddressCommon, make([]byte, 0), 2000000)
	resp := s.deliverEthTx(sender, msgEthereumTx)
	s.Require().True(resp.IsOK(), resp.GetLog(), resp.GetLog())
	s.Commit()

	// s.Require().True(false, "---")
}

// func (suite *KeeperTestSuite) TestEwasmOpcodes() {
// 	// wasmbin := opcodeswasm
// 	wasmbin := opcodesyulwasm
// 	sender := suite.GetRandomAccount()
// 	initBalance := sdk.NewInt(1000_000_000)

// 	suite.faucet.Fund(suite.ctx, sender.Address, sdk.NewCoin(suite.denom, initBalance))
// 	suite.Commit()

// 	permission := &wasmtypes.AccessConfig{
// 		Permission: wasmtypes.AccessTypeEverybody,
// 	}
// 	storeCodeMsg := &wasmtypes.MsgStoreCode{
// 		Sender:                sender.Address.String(),
// 		WASMByteCode:          wasmbin,
// 		InstantiatePermission: permission,
// 	}

// 	res := suite.DeliverTx(sender, storeCodeMsg)
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	codeId := suite.GetCodeIdFromLog(res.GetLog())

// 	bytecode, err := suite.app.EwasmKeeper.TwasmKeeper.GetByteCode(suite.ctx, codeId)
// 	s.Require().NoError(err)
// 	s.Require().Equal(bytecode, wasmbin)

// 	instantiateMsg := []byte(`{"data": "0x"}`)
// 	instantiateCodeMsg := &wasmtypes.MsgInstantiateContract{
// 		Sender: sender.Address.String(),
// 		CodeID: codeId,
// 		Label:  "test",
// 		Msg:    instantiateMsg,
// 	}
// 	res = suite.DeliverTxWithOpts(sender, instantiateCodeMsg, 235690, nil) // 135690
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	contractAddress := suite.GetContractAddressFromLog(res.GetLog())

// 	executeMsg := []byte(`{"data": "0x0022"}`)
// 	executeCodeMsg := &wasmtypes.MsgExecuteContract{
// 		Sender:   sender.Address.String(),
// 		Contract: contractAddress,
// 		Msg:      executeMsg,
// 		Funds:    sdk.Coins{},
// 	}
// 	res = suite.DeliverTxWithOpts(sender, executeCodeMsg, 235690, nil) // 135690
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	// s.Require().True(false, "---")
// }

// func (suite *KeeperTestSuite) TestEwasmWithoutConstructorArgs() {
// 	wasmbin := cwoargsprintwasm3
// 	sender := suite.GetRandomAccount()
// 	initBalance := sdk.NewInt(1000_000_000)

// 	suite.faucet.Fund(suite.ctx, sender.Address, sdk.NewCoin(suite.denom, initBalance))
// 	suite.Commit()

// 	permission := &wasmtypes.AccessConfig{
// 		Permission: wasmtypes.AccessTypeEverybody,
// 	}
// 	storeCodeMsg := &wasmtypes.MsgStoreCode{
// 		Sender:                sender.Address.String(),
// 		WASMByteCode:          wasmbin,
// 		InstantiatePermission: permission,
// 	}

// 	res := suite.DeliverTx(sender, storeCodeMsg)
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	codeId := suite.GetCodeIdFromLog(res.GetLog())

// 	bytecode, err := suite.app.EwasmKeeper.TwasmKeeper.GetByteCode(suite.ctx, codeId)
// 	s.Require().NoError(err)
// 	s.Require().Equal(bytecode, wasmbin)

// 	instantiateMsg := []byte(`{}`)

// 	instantiateCodeMsg := &wasmtypes.MsgInstantiateContract{
// 		Sender: sender.Address.String(),
// 		CodeID: codeId,
// 		Label:  "test",
// 		Msg:    instantiateMsg,
// 	}
// 	res = suite.DeliverTxWithOpts(sender, instantiateCodeMsg, 235690, nil) // 135690
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	contractAddressStr := suite.GetContractAddressFromLog(res.GetLog())
// 	contractAddress := sdk.MustAccAddressFromBech32(contractAddressStr)

// 	keybz := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
// 	queryres := s.app.EwasmKeeper.TwasmKeeper.QueryRaw(suite.ctx, contractAddress, keybz)
// 	suite.Require().Equal("000000000000000000000000"+hex.EncodeToString(sender.Address.Bytes()), hex.EncodeToString(queryres))
// }

// func (suite *KeeperTestSuite) TestWasm() {
// 	wasmbin := erc20cw
// 	sender := suite.GetRandomAccount()
// 	initBalance := sdk.NewInt(1000_000_000)

// 	suite.faucet.Fund(suite.ctx, sender.Address, sdk.NewCoin(suite.denom, initBalance))
// 	suite.Commit()

// 	// senderBalance := suite.app.EwasmKeeper.BankKeeper.GetBalance(suite.ctx, sender.Address, suite.denom)
// 	// fmt.Println("---senderBalance", senderBalance)

// 	permission := &wasmtypes.AccessConfig{
// 		Permission: wasmtypes.AccessTypeEverybody,
// 	}
// 	storeCodeMsg := &wasmtypes.MsgStoreCode{
// 		Sender:                sender.Address.String(),
// 		WASMByteCode:          wasmbin,
// 		InstantiatePermission: permission,
// 	}

// 	res := suite.DeliverTx(sender, storeCodeMsg)
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	codeId := suite.GetCodeIdFromLog(res.GetLog())

// 	instantiateMsgRaw := `{"name":"Token","symbol":"TKN","decimals":6,"initial_supply":"10000000000","mint_denom":"utgd"}`
// 	instantiateMsg := []byte(instantiateMsgRaw)

// 	instantiateCodeMsg := &wasmtypes.MsgInstantiateContract{
// 		Sender: sender.Address.String(),
// 		CodeID: codeId,
// 		Label:  "test",
// 		Msg:    instantiateMsg,
// 	}
// 	res = suite.DeliverTx(sender, instantiateCodeMsg)
// 	s.Require().True(res.IsOK(), res.GetLog())
// 	suite.Commit()

// 	contractAddressStr := suite.GetContractAddressFromLog(res.GetLog())
// 	contractAddress := sdk.MustAccAddressFromBech32(contractAddressStr)

// 	querybz := []byte(`{"name":{}}`)
// 	queryres, err := s.app.EwasmKeeper.TwasmKeeper.QuerySmart(suite.ctx, contractAddress, querybz)
// 	s.Require().NoError(err)
// 	suite.Require().Equal(`{"value":"Token"}`, string(queryres))

// 	keybz := []byte(`owner`)
// 	queryres = s.app.EwasmKeeper.TwasmKeeper.QueryRaw(suite.ctx, contractAddress, keybz)
// 	suite.Require().Equal("\""+sender.Address.String()+"\"", string(queryres))
// }
