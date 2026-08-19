package server

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/noblifi/noblifi/backend/internal/auth"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/provisioning"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
)

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

	api.Get("/dashboard/stats", func(c *fiber.Ctx) error {
		var routerCount int64
		var activeRouterCount int64
		var userCount int64
		var activeSessionCount int64
		var dataUsage struct {
			UploadBytes   int64
			DownloadBytes int64
		}

		_ = db.Model(&routers.Router{}).Where("deleted_at IS NULL").Count(&routerCount).Error
		_ = db.Model(&routers.Router{}).Where("deleted_at IS NULL AND last_seen_at IS NOT NULL").Count(&activeRouterCount).Error
		_ = db.Model(&database.User{}).Count(&userCount).Error
		_ = db.Model(&database.Session{}).Where("status = ? AND stopped_at IS NULL", "active").Count(&activeSessionCount).Error
		_ = db.Model(&database.Session{}).Select("COALESCE(SUM(upload_bytes), 0) AS upload_bytes, COALESCE(SUM(download_bytes), 0) AS download_bytes").Scan(&dataUsage).Error

		return c.JSON(fiber.Map{
			"routers": fiber.Map{
				"total":  routerCount,
				"online": activeRouterCount,
			},
			"users": fiber.Map{
				"total":           userCount,
				"active_sessions": activeSessionCount,
			},
			"data_usage": fiber.Map{
				"upload_bytes":   dataUsage.UploadBytes,
				"download_bytes": dataUsage.DownloadBytes,
				"total_bytes":    dataUsage.UploadBytes + dataUsage.DownloadBytes,
			},
			"router_cpu_usage": nil,
		})
	})

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

	// No EnsureVoucherConsumptionHooks call is required in the current
	// RadiusService. Voucher activation/device binding is handled by
	// AuthorizeVoucherForDevice/BindVoucherToDevice.

	// ---------------------------------------------------------
	// ROUTERS
	// ---------------------------------------------------------

	routerRepo := routers.NewRepository(db)

	routerService := routers.NewService(
		routerRepo,
		cfg,
	)

	wireGuardControlPlane := wireguard.NewService(db, cfg)
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
	)

	// Online hotspot purchases create their voucher after payment succeeds, so
	// no pre-generated online-voucher pool is required here.
	plans.NewHandler(
		planService,
		nil,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// VOUCHERS
	// ---------------------------------------------------------
	//
	// Voucher generation persists voucher records only. The captive-portal
	// device-bind path in RadiusService creates/refreshes the FreeRADIUS SQL
	// credential before MikroTik submits the voucher login. Existing vouchers
	// are also synchronized during startup below.
	//

	voucherRepo := vouchers.NewRepository(db)

	voucherService := vouchers.NewService(
		voucherRepo,
	)

	vouchers.NewHandler(
		voucherService,
	).RegisterRoutes(api)

	paymentService := payments.NewService(
		db,
		cfg,
		radiusService,
	)

	if err := paymentService.EnsureHotspotPurchaseSchema(); err != nil {
		log.Fatalf(
			"migrate hotspot purchases: %v",
			err,
		)
	}

	payments.NewHandler(
		paymentService,
	).RegisterRoutes(api)

	// ---------------------------------------------------------
	// PROVISIONING
	// ---------------------------------------------------------

	// The current provisioning constructor intentionally remains four
	// arguments. HotSpot commerce dependencies are attached explicitly below.
	provisioningService := provisioning.NewService(
		routerRepo,
		cfg,
		radiusService,
		wireGuardControlPlane,
	)

	// CRITICAL: without this setter activePortalPlans sees s.plans == nil and
	// the captive portal renders "No packages are available right now."
	provisioningService.SetPlanLister(
		planService,
	)

	// Enables the Buy button and the mobile-money purchase/status flow.
	provisioningService.SetHotspotPaymentService(
		paymentService,
	)

	provisioningHandler := provisioning.NewHandler(
		provisioningService,
	)
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
			"version": "2026-08-20-hotspot-plan-commerce",
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
