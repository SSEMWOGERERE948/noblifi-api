package database

import (
	"log"
	"os"
	"time"

	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(databaseURL string) (*gorm.DB, error) {
	return gorm.Open(postgres.New(postgres.Config{
		DSN:                  databaseURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		}),
	})
}

func AutoMigrate(db *gorm.DB) error {
	if db.Migrator().HasTable(&radius.RadAcct{}) {
		if err := db.Exec("UPDATE radacct SET groupname = '' WHERE groupname IS NULL").Error; err != nil {
			return err
		}
	}

	if err := db.AutoMigrate(
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
		&routers.RouterDeleteChallenge{},
		&wireguard.WireGuardJob{},
		&wireguard.AgentHeartbeat{},
		&radius.RadCheck{},
		&radius.RadReply{},
		&radius.RadAcct{},
		&radius.NAS{},
		&plans.Plan{},
		&vouchers.Voucher{},
		&Session{},
	); err != nil {
		return err
	}

	return ensureRouterPartialUniqueIndexes(db)
}

func ensureRouterPartialUniqueIndexes(db *gorm.DB) error {
	// GORM's uniqueIndex tag creates plain unique indexes across all rows,
	// including soft-deleted routers. Replace those indexes with partial
	// indexes so deleted records cannot block re-provisioning the same device.
	return db.Exec(`
DROP INDEX IF EXISTS idx_routers_serial_number;
CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_serial_number_active
	ON routers (serial_number)
	WHERE deleted_at IS NULL AND serial_number IS NOT NULL;

DROP INDEX IF EXISTS idx_routers_claim_token;
CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_claim_token_active
	ON routers (claim_token)
	WHERE deleted_at IS NULL AND claim_token IS NOT NULL AND claim_token <> '';
`).Error
}
