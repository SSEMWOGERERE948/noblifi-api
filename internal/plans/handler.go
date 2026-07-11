package plans

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
	router.Post("/plans", h.create)
	router.Get("/plans", h.list)
	router.Get("/plans/:id", h.get)
	router.Patch("/plans/:id", h.patch)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var plan Plan
	if err := c.BodyParser(&plan); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	created, err := h.service.Create(plan)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h *Handler) list(c *fiber.Ctx) error {
	plans, err := h.service.List()
	if err != nil {
		return err
	}
	return c.JSON(plans)
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid plan id")
	}
	plan, err := h.service.Find(id)
	if err != nil {
		return err
	}
	return c.JSON(plan)
}

func (h *Handler) patch(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid plan id")
	}
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	plan, err := h.service.Patch(id, input)
	if err != nil {
		return err
	}
	return c.JSON(plan)
}
