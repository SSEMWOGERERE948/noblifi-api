package vouchers

import (
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
	router.Post("/vouchers/generate", h.generate)
	router.Get("/vouchers", h.list)
}

func (h *Handler) generate(c *fiber.Ctx) error {
	var input struct {
		PlanID   string `json:"plan_id"`
		Quantity int    `json:"quantity"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	planID, err := uuid.Parse(input.PlanID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid plan id")
	}
	generated, err := h.service.Generate(planID, input.Quantity)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(generated)
}

func (h *Handler) list(c *fiber.Ctx) error {
	vouchers, err := h.service.List()
	if err != nil {
		return err
	}
	return c.JSON(vouchers)
}
