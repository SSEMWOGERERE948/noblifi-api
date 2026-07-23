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
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,PATCH,DELETE,OPTIONS",
	}))

	api := app.Group("/api/v1")

	authService := auth.NewService(db, cfg.JWTSecret)
	if err := authService.SeedAdmin(); err != nil {
		log.Printf("seed admin failed: %v", err)
	}
	auth.NewHandler(authService).RegisterRoutes(api)

	routerRepo := routers.NewRepository(db)
	radiusService := radius.NewService(db)
	radiusService.StartUDPServers(cfg.RadiusAuthPort, cfg.RadiusAcctPort, cfg.RadiusSecret)
	routerService := routers.NewService(routerRepo, cfg)
	planRepo := plans.NewRepository(db)
	planService := plans.NewService(planRepo)
	routers.NewHandler(routerService).RegisterRoutes(api)
	provisioning.NewHandler(provisioning.NewService(routerRepo, cfg, radiusService, planService)).RegisterRoutes(api)

	plans.NewHandler(planService).RegisterRoutes(api)

	radius.NewHandler(radiusService).RegisterRoutes(api)

	voucherRepo := vouchers.NewRepository(db)
	voucherService := vouchers.NewService(voucherRepo)
	voucherService.SetRadiusSyncer(radiusService)
	vouchers.NewHandler(voucherService).RegisterRoutes(api)

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
