package radius

import "github.com/gofiber/fiber/v2"

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/radius/vouchers/:code/sync", h.syncVoucher)
	router.Post("/radius/vouchers/sync", h.syncAllVouchers)
	router.Get("/radius/accounting/summary", h.accountingSummary)
}

func (h *Handler) syncVoucher(c *fiber.Ctx) error {
	state, err := h.service.SyncVoucher(c.Params("code"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(state)
}

func (h *Handler) syncAllVouchers(c *fiber.Ctx) error {
	count, err := h.service.SyncAllVouchers()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"synced": count})
}

func (h *Handler) accountingSummary(c *fiber.Ctx) error {
	summary, err := h.service.AccountingSummary()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(summary)
}
