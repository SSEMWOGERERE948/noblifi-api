package plans

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	service          *Service
	voucherGenerator OnlineVoucherGenerator
}

type OnlineVoucherGenerator interface {
	GenerateOnlineVoucherCount(planID uuid.UUID, userID *uuid.UUID, isSuperadmin bool) (int, error)
}

func NewHandler(service *Service, voucherGenerator OnlineVoucherGenerator) *Handler {
	return &Handler{service: service, voucherGenerator: voucherGenerator}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/plans", h.create)
	router.Patch("/plans/:id", h.patch)
}

func (h *Handler) RegisterPublicRoutes(router fiber.Router) {
	router.Get("/plans", h.list)
	router.Get("/plans/:id", h.get)
}

type currentUser interface {
	GetID() uuid.UUID
	GetRole() string
	TrialExpired() bool
}

func (h *Handler) create(c *fiber.Ctx) error {
	if user, ok := c.Locals("user").(currentUser); ok && user.TrialExpired() {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "your free trial has expired. Please subscribe to continue."})
	}

	var plan Plan
	if err := c.BodyParser(&plan); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	userID, isSuperadmin := currentUserScope(c)
	created, err := h.service.Create(plan, userID, isSuperadmin)
	if err != nil {
		return err
	}
	if h.voucherGenerator != nil {
		count, err := h.voucherGenerator.GenerateOnlineVoucherCount(created.ID, userID, isSuperadmin)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "plan created but mobile money online vouchers could not be generated: "+err.Error())
		}
		created.OnlineVouchersCreated = count
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h *Handler) list(c *fiber.Ctx) error {
	userID, isSuperadmin := currentUserScope(c)
	plans, err := h.service.List(userID, isSuperadmin)
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
	userID, isSuperadmin := currentUserScope(c)
	plan, err := h.service.Find(id, userID, isSuperadmin)
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
	userID, isSuperadmin := currentUserScope(c)
	plan, err := h.service.Patch(id, input, userID, isSuperadmin)
	if err != nil {
		return err
	}
	return c.JSON(plan)
}

func currentUserScope(c *fiber.Ctx) (*uuid.UUID, bool) {
	user, ok := c.Locals("user").(interface {
		GetID() uuid.UUID
		GetRole() string
	})
	if !ok {
		return nil, false
	}
	id := user.GetID()
	return &id, user.GetRole() == "superadmin"
}
