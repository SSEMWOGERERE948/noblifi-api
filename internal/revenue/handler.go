package revenue

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
	"gorm.io/gorm"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Get("/revenue/summary", h.summary)
	router.Get("/revenue/by-hotspot", h.byHotspot)
	router.Get("/revenue/by-package", h.byPackage)
	router.Get("/revenue/trend", h.trend)
	router.Get("/revenue/transactions", h.transactions)
	router.Get("/routers/:id/revenue/summary", h.routerSummary)

	router.Get("/admin/revenue/platform-summary", h.adminPlatformSummary)
	router.Get("/admin/revenue/online-token-fees", h.adminTokenRevenue)
	router.Get("/admin/revenue/subscriptions", h.adminSubscriptionRevenue)
	router.Get("/admin/revenue/accounts", h.adminUserAccounts)
	router.Get("/admin/revenue/accounts/:user_id/statement", h.adminUserStatement)
}

func (h *Handler) summary(c *fiber.Ctx) error {
	out, err := h.service.Summary(scope(c), filters(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load revenue summary")
	}
	return c.JSON(out)
}

func (h *Handler) byHotspot(c *fiber.Ctx) error {
	out, err := h.service.ByHotspot(scope(c), filters(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load hotspot revenue")
	}
	return c.JSON(out)
}

func (h *Handler) byPackage(c *fiber.Ctx) error {
	out, err := h.service.ByPackage(scope(c), filters(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load package revenue")
	}
	return c.JSON(out)
}

func (h *Handler) trend(c *fiber.Ctx) error {
	out, err := h.service.Trend(scope(c), filters(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load revenue trend")
	}
	return c.JSON(out)
}

func (h *Handler) transactions(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "25"))
	out, err := h.service.Transactions(scope(c), filters(c), limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load revenue transactions")
	}
	return c.JSON(out)
}

func (h *Handler) routerSummary(c *fiber.Ctx) error {
	routerID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	out, err := h.service.RouterSummary(scope(c), routerID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return fiber.NewError(fiber.StatusNotFound, "router not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "could not load router revenue")
	}
	return c.JSON(out)
}

func (h *Handler) adminPlatformSummary(c *fiber.Ctx) error {
	out, err := h.service.AdminPlatformSummary(scope(c), filters(c))
	if err != nil {
		return adminRevenueError(err, "could not load platform revenue")
	}
	return c.JSON(out)
}

func (h *Handler) adminTokenRevenue(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	out, err := h.service.AdminTokenRevenue(scope(c), filters(c), limit)
	if err != nil {
		return adminRevenueError(err, "could not load online token fees")
	}
	return c.JSON(out)
}

func (h *Handler) adminSubscriptionRevenue(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	out, err := h.service.AdminSubscriptionRevenue(scope(c), filters(c), limit)
	if err != nil {
		return adminRevenueError(err, "could not load subscription revenue")
	}
	return c.JSON(out)
}

func (h *Handler) adminUserAccounts(c *fiber.Ctx) error {
	out, err := h.service.UserAccountSummaries(scope(c), filters(c))
	if err != nil {
		return adminRevenueError(err, "could not load user accounts")
	}
	return c.JSON(out)
}

func (h *Handler) adminUserStatement(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid user id")
	}
	limit, _ := strconv.Atoi(c.Query("limit", "500"))
	out, err := h.service.UserStatement(scope(c), userID, filters(c), limit)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return fiber.NewError(fiber.StatusNotFound, "user not found")
		}
		return adminRevenueError(err, "could not load user statement")
	}
	return c.JSON(out)
}

func adminRevenueError(err error, fallback string) error {
	if strings.Contains(strings.ToLower(err.Error()), "superadmin role required") {
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	}
	return fiber.NewError(fiber.StatusInternalServerError, fallback)
}

func scope(c *fiber.Ctx) Scope {
	user, _ := c.Locals("user").(database.User)
	return Scope{
		UserID: user.ID, IsSuperadmin: strings.EqualFold(strings.TrimSpace(user.Role), "superadmin"),
	}
}

func filters(c *fiber.Ctx) Filters {
	return Filters{
		RouterID: strings.TrimSpace(c.Query("router_id")),
		PlanID:   strings.TrimSpace(c.Query("plan_id")),
		Provider: strings.TrimSpace(c.Query("provider")),
		Status:   strings.TrimSpace(c.Query("status")),
		Range:    strings.TrimSpace(c.Query("range")),
		From:     parseDate(c.Query("from")),
		To:       parseDate(c.Query("to")),
	}
}

func parseDate(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return &parsed
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return &parsed
	}
	return nil
}
