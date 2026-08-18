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
	cfg := config.Load()
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	app := fiber.New(fiber.Config{AppName: "NobliFi API"})
	app.Use(cors.New(cors.Config{
		AllowOrigins: "https://noblifi-frontend.vercel.app,http://localhost:3000,http://localhost:3001,http://localhost:3002",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,PATCH,DELETE,OPTIONS",
	}))

	api := app.Group("/api/v1")

	// --- Services (no routes registered yet) ---
	authService := auth.NewService(db, cfg.JWTSecret)
	if err := authService.SeedAdmin(); err != nil {
		log.Printf("seed admin failed: %v", err)
	}
	authHandler := auth.NewHandler(authService)

	routerRepo := routers.NewRepository(db)
	radiusService := radius.NewService(db)
	radiusService.StartUDPServers(cfg.RadiusAuthPort, cfg.RadiusAcctPort, cfg.RadiusSecret)
	routerService := routers.NewService(routerRepo, cfg)
	wireGuardService := wireguard.NewService(db, cfg)
	routerService.SetWireGuardServerPublicKeyResolver(wireGuardService)
	planRepo := plans.NewRepository(db)
	planService := plans.NewService(planRepo)
	voucherRepo := vouchers.NewRepository(db)
	voucherService := vouchers.NewService(voucherRepo)
	voucherService.SetRadiusSyncer(radiusService)
	paymentsService := payments.NewService(db, cfg, radiusService)
	provisioningService := provisioning.NewService(routerRepo, cfg, radiusService, wireGuardService)

	// --- Register every PUBLIC route BEFORE the protected group exists. ---
	// IMPORTANT: In Fiber v2, api.Group("", authHandler.RequireAuth) attaches
	// RequireAuth as prefix middleware on "/api/v1" itself. Any route registered
	// on `api` (or any group sharing that prefix) AFTER that call also inherits
	// RequireAuth, even though it was never passed the `protected` variable.
	// Registering all public routes first avoids that trap.
	authHandler.RegisterRoutes(api)
	payments.NewHandler(paymentsService).RegisterRoutes(api)
	plans.NewHandler(planService, voucherService).RegisterPublicRoutes(api)
	provisioning.NewHandler(provisioningService).RegisterRoutes(api)
	radius.NewHandler(radiusService).RegisterRoutes(api)
	wireguard.NewHandler(wireGuardService).RegisterRoutes(api)

	// --- NOW create the protected group and register everything requiring auth. ---
	protected := api.Group("", authHandler.RequireAuth)
	routers.NewHandler(routerService).RegisterRoutes(protected)
	plans.NewHandler(planService, voucherService).RegisterRoutes(protected)
	vouchers.NewHandler(voucherService).RegisterRoutes(protected)
	paymentsProtected := protected.Group("")
	payments.NewHandler(paymentsService).RegisterProtectedRoutes(paymentsProtected)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"service": "noblifi-api",
			"status":  "running",
			"version": "2026-07-04-router-provisioning",
		})
	})

	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "noblifi-api",
		})
	})

	app.Get("/debug/routes", func(c *fiber.Ctx) error {
		routes := app.GetRoutes()
		out := make([]string, 0, len(routes))

		for _, route := range routes {
			out = append(out, route.Method+" "+route.Path)
		}

		return c.JSON(out)
	})

	log.Fatal(app.Listen(":" + cfg.Port))
}
