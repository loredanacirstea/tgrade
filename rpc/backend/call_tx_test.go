package backend

import (
	"github.com/confio/tgrade/rpc/backend/mocks"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func (suite *BackendTestSuite) TestSendRawTransaction() {
	ethTx, _ := suite.buildEthereumTx()
	rlpEncodedBz, _ := rlp.EncodeToBytes(ethTx.AsTransaction())
	cosmosTx, _ := ethTx.BuildTx(suite.backend.clientCtx.TxConfig.NewTxBuilder(), "aphoton")
	txBytes, _ := suite.backend.clientCtx.TxConfig.TxEncoder()(cosmosTx)

	expectedHash := common.HexToHash(ethTx.Hash)

	suite.SetupTest() // reset test and queries
	client := suite.backend.clientCtx.Client.(*mocks.Client)
	queryClient := suite.backend.queryClient.QueryClient.(*mocks.QueryClient)
	suite.backend.allowUnprotectedTxs = true
	RegisterParamsWithoutHeader(queryClient, 1)
	RegisterBroadcastTx(client, txBytes)

	hash, err := suite.backend.SendRawTransaction(rlpEncodedBz)
	suite.Require().NoError(err)
	suite.Require().Equal(expectedHash, hash)
	suite.Require().Equal(1, 2)
}
