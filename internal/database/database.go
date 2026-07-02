package database

import (
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect(databaseURL string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&Site{},
		&routers.Router{},
		&routers.RouterSetupSession{},
		&routers.RouterNetworkProfile{},
		&routers.RouterInterface{},
		&routers.RouterPortAssignment{},
		&routers.RouterConfigLog{},
		&radius.RadCheck{},
		&radius.RadReply{},
		&radius.RadAcct{},
		&radius.NAS{},
		&plans.Plan{},
		&vouchers.Voucher{},
		&Session{},
	)
}
