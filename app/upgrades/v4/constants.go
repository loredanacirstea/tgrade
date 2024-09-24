package v4

import (
	"github.com/confio/tgrade/app/upgrades"
)

// UpgradeName defines the on-chain upgrade name for the Tgrade v4 upgrade.
const UpgradeName = "v4"

var Upgrade = upgrades.Upgrade{
	UpgradeName:          UpgradeName,
	CreateUpgradeHandler: CreateUpgradeHandler,
}
