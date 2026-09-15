package radius

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/radius/plans/sync", h.syncAllPlans)

	router.Post("/radius/vouchers/:code/sync", h.syncVoucher)
	router.Post("/radius/vouchers/sync", h.syncAllVouchers)

	router.Get("/radius/accounting/summary", h.accountingSummary)
}

func (h *Handler) syncVoucher(c *fiber.Ctx) error {
	if err := requireSuperadmin(c); err != nil {
		return err
	}
	state, err := h.service.SyncVoucher(c.Params("code"))
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(state)
}

func (h *Handler) syncAllPlans(c *fiber.Ctx) error {
	if err := requireSuperadmin(c); err != nil {
		return err
	}
	count, err := h.service.SyncAllPlans()
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(fiber.Map{
		"synced": count,
	})
}

func (h *Handler) syncAllVouchers(c *fiber.Ctx) error {
	if err := requireSuperadmin(c); err != nil {
		return err
	}
	count, err := h.service.SyncAllVouchers()
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(fiber.Map{
		"synced": count,
	})
}

func (h *Handler) accountingSummary(c *fiber.Ctx) error {
	user, ok := c.Locals("user").(interface {
		GetID() uuid.UUID
		GetRole() string
	})
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authenticated user"})
	}

	var summary map[string]any
	var err error
	if strings.EqualFold(strings.TrimSpace(user.GetRole()), "superadmin") {
		summary, err = h.service.AccountingSummary()
	} else {
		summary, err = h.service.AccountingSummaryForUser(user.GetID())
	}
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(summary)
}

func requireSuperadmin(c *fiber.Ctx) error {
	user, ok := c.Locals("user").(interface {
		GetRole() string
	})
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authenticated user"})
	}
	if !strings.EqualFold(strings.TrimSpace(user.GetRole()), "superadmin") {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "superadmin role required"})
	}
	return nil
}
