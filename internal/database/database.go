package database

import (
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect(databaseURL string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
}

func AutoMigrate(db *gorm.DB) error {
	if db.Migrator().HasTable(&radius.RadAcct{}) {
		if err := db.Exec("UPDATE radacct SET groupname = '' WHERE groupname IS NULL").Error; err != nil {
			return err
		}
	}

	return db.AutoMigrate(
		&User{},
		&AppSetting{},
		&AuthCode{},
		&Site{},
		&routers.Router{},
		&routers.RouterSetupSession{},
		&routers.RouterNetworkProfile{},
		&routers.RouterInterface{},
		&routers.RouterPortAssignment{},
		&routers.RouterConfigLog{},
		&wireguard.WireGuardJob{},
		&wireguard.AgentHeartbeat{},
		&radius.RadCheck{},
		&radius.RadReply{},
		&radius.RadAcct{},
		&radius.NAS{},
		&plans.Plan{},
		&vouchers.Voucher{},
		&Session{},
	)
}
