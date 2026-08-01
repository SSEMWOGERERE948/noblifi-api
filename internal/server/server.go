package server

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/noblifi/noblifi/backend/internal/auth"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/provisioning"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
)

type radiusSyncAdapter struct{ r *radius.Service }

func (a radiusSyncAdapter) SyncVoucherForVoucher(v vouchers.Voucher) error {
	return a.r.SyncVoucherForVoucher(v.Code)
}

type wireGuardCleanupAdapter struct{ w *wireguard.Service }

func (a wireGuardCleanupAdapter) QueuePeerRemoval(router routers.Router) error {
	_, err := a.w.QueuePeerRemoval(router)
	return err
}

func Run() {
	// ---------------------------------------------------------
	// CONFIGURATION
	// ---------------------------------------------------------

	cfg := config.Load()

	// ---------------------------------------------------------
	// DATABASE
	// ---------------------------------------------------------

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}

	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	// ---------------------------------------------------------
	// FIBER
	// ---------------------------------------------------------

	app := fiber.New(fiber.Config{
		AppName: "NobliFi API",
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,PATCH,DELETE,OPTIONS",
	}))

	api := app.Group("/api/v1")

	// ---------------------------------------------------------
	// AUTH
	// ---------------------------------------------------------

	authService := auth.NewService(
		db,
		cfg.JWTSecret,
	)

	if err := authService.SeedAdmin(); err != nil {
		log.Printf("seed admin failed: %v", err)
	}

	auth.NewHandler(
		authService,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// RADIUS
	// ---------------------------------------------------------
	//
	// IMPORTANT:
	//
	// NobliFi API is NOT the UDP RADIUS server anymore.
	//
	// FreeRADIUS running on the VPS owns:
	//
	// UDP 1812 -> authentication
	// UDP 1813 -> accounting
	//
	// This service manages the RADIUS SQL tables used by
	// FreeRADIUS:
	//
	// radcheck
	// radreply
	// radgroupcheck
	// radgroupreply
	// radusergroup
	// radacct
	// nas
	//
	// Therefore DO NOT call:
	//
	// radiusService.StartUDPServers(...)
	//

	radiusService := radius.NewService(db)

	// ---------------------------------------------------------
	// ROUTERS
	// ---------------------------------------------------------

	routerRepo := routers.NewRepository(db)

	routerService := routers.NewService(
		routerRepo,
		cfg,
	)

	wireGuardControlPlane := wireguard.NewService(db, cfg)
	routerService.SetWireGuardCleanup(wireGuardCleanupAdapter{w: wireGuardControlPlane})
	routerService.SetWireGuardServerPublicKeyResolver(wireGuardControlPlane)

	routers.NewHandler(
		routerService,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// PLANS / PACKAGES
	// ---------------------------------------------------------
	//
	// Plans are stored in the normal NobliFi plans table,
	// but the RadiusService creates and maintains their
	// corresponding FreeRADIUS group policy.
	//

	planRepo := plans.NewRepository(db)

	planService := plans.NewService(
		planRepo,
		radiusService,
	)

	plans.NewHandler(
		planService,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// VOUCHERS
	// ---------------------------------------------------------
	//
	// Every generated voucher is now automatically inserted
	// into FreeRADIUS SQL through RadiusService.
	//
	// There is no SetRadiusSyncer() call anymore.
	//

	voucherRepo := vouchers.NewRepository(db)

	voucherService := vouchers.NewService(
		voucherRepo,
		radiusSyncAdapter{r: radiusService},
	)

	vouchers.NewHandler(
		voucherService,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// PROVISIONING
	// ---------------------------------------------------------

	provisioningService := provisioning.NewService(
		routerRepo,
		cfg,
		radiusService,
		planService,
		wireGuardControlPlane,
	)

	provisioningHandler := provisioning.NewHandler(
		provisioningService,
	)
	provisioningHandler.SetAgentAuthenticator(wireGuardControlPlane)
	provisioningHandler.RegisterRoutes(api)

	// ---------------------------------------------------------
	// RADIUS MANAGEMENT API
	// ---------------------------------------------------------
	//
	// Provides endpoints such as:
	//
	// POST /api/v1/radius/plans/sync
	// POST /api/v1/radius/vouchers/sync
	// POST /api/v1/radius/vouchers/:code/sync
	// GET  /api/v1/radius/accounting/summary
	//

	radius.NewHandler(
		radiusService,
	).RegisterRoutes(api)

	wireguard.NewHandler(
		wireGuardControlPlane,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// EXISTING DATA RADIUS SYNC
	// ---------------------------------------------------------
	//
	// This is useful while migrating the existing NobliFi
	// database to the new FreeRADIUS SQL architecture.
	//
	// Failure does not stop the API because an old package may
	// contain invalid data such as duration_minutes=0.
	//

	if count, err := radiusService.SyncAllPlans(); err != nil {
		log.Printf(
			"initial RADIUS plan sync failed: %v",
			err,
		)
	} else {
		log.Printf(
			"initial RADIUS plan sync completed: %d plans",
			count,
		)
	}

	if count, err := radiusService.SyncAllVouchers(); err != nil {
		log.Printf(
			"initial RADIUS voucher sync failed: %v",
			err,
		)
	} else {
		log.Printf(
			"initial RADIUS voucher sync completed: %d vouchers",
			count,
		)
	}

	// ---------------------------------------------------------
	// ROOT
	// ---------------------------------------------------------

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"service": "noblifi-api",
			"status":  "running",
			"version": "2026-07-26-freeradius-sql",
		})
	})

	// ---------------------------------------------------------
	// HEALTH CHECK
	// ---------------------------------------------------------

	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "noblifi-api",
		})
	})

	// ---------------------------------------------------------
	// DEBUG ROUTES
	// ---------------------------------------------------------

	app.Get("/debug/routes", func(c *fiber.Ctx) error {
		routes := app.GetRoutes()

		out := make([]string, 0, len(routes))

		for _, route := range routes {
			out = append(
				out,
				route.Method+" "+route.Path,
			)
		}

		return c.JSON(out)
	})

	// ---------------------------------------------------------
	// START HTTP SERVER
	// ---------------------------------------------------------

	log.Printf(
		"NobliFi API starting on port %s",
		cfg.Port,
	)

	log.Fatal(
		app.Listen(":" + cfg.Port),
	)
}
