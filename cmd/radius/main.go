package main

import (
	"log"

	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/radius"
)

func main() {
	cfg := config.Load()

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}

	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("database migration: %v", err)
	}

	radiusService := radius.NewService(db)
	radiusService.StartUDPServers(
		cfg.RadiusAuthPort,
		cfg.RadiusAcctPort,
		cfg.RadiusSecret,
	)

	log.Printf(
		"NobliFi RADIUS started: authentication UDP %d, accounting UDP %d",
		cfg.RadiusAuthPort,
		cfg.RadiusAcctPort,
	)

	select {}
}
