package keeper_test

import (
	"github.com/confio/tgrade/x/ewasm/types"
)

func (suite *KeeperTestSuite) TestParams() {
	params := suite.app.EwasmKeeper.GetParams(suite.ctx)
	params.EnableEwasm = false
	suite.Require().Equal(types.DefaultParams(), params)
	params.EnableEwasm = true
	suite.app.EwasmKeeper.SetParams(suite.ctx, params)
	newParams := suite.app.EwasmKeeper.GetParams(suite.ctx)
	suite.Require().Equal(newParams, params)
}
