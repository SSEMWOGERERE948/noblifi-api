package database

import (
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect(databaseURL string) (*gorm.DB, error) {

	return gorm.Open(postgres.New(postgres.Config{
		DSN:                  databaseURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&ConfirmationCode{},
		&RouterLimitRequest{},
		&Site{},

		// Router models
		&routers.Router{},
		&routers.RouterSetupSession{},
		&routers.RouterNetworkProfile{},
		&routers.RouterInterface{},
		&routers.RouterPortAssignment{},
		&routers.RouterConfigLog{},
		&wireguard.WireGuardJob{},
		&wireguard.AgentHeartbeat{},

		// FreeRADIUS SQL models
		&radius.RadCheck{},
		&radius.RadReply{},
		&radius.RadGroupCheck{},
		&radius.RadGroupReply{},
		&radius.RadUserGroup{},
		&radius.RadPostAuth{},
		&radius.RadAcct{},
		&radius.NAS{},

		// NobliFi commercial models
		&plans.Plan{},
		&payments.PaymentOrder{},
		&vouchers.Voucher{},

		&Session{},
	)
}
