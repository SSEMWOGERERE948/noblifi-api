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
	// PreferSimpleProtocol disables GORM/pgx's prepared statement caching.
	//
	// Neon's pooled connection strings route through PgBouncer in
	// transaction-pooling mode, which can hand the same underlying Postgres
	// connection to different logical sessions. GORM's default prepared
	// statement cache is keyed per-connection, so a statement name cached
	// client-side can collide with one already prepared under a different
	// session on that same underlying connection - causing intermittent
	// "prepared statement already in use" (SQLSTATE 08P01) errors under
	// concurrent load, e.g. when generating a batch of vouchers.
	return gorm.Open(postgres.New(postgres.Config{
		DSN:                  databaseURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})
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
		&radius.RadGroupCheck{},
		&radius.RadGroupReply{},
		&radius.RadUserGroup{},
		&radius.RadAcct{},
		&radius.NAS{},
		&plans.Plan{},
		&vouchers.Voucher{},
		&Session{},
	)
}