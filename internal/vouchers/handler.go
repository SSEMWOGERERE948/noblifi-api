package vouchers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/vouchers/generate", h.generate)
	router.Get("/vouchers", h.list)
}

func (h *Handler) generate(c *fiber.Ctx) error {
	userID, isSuperadmin := currentUserScope(c)

	/*
		Do not restrict the platform superadmin.

		For normal users, use the newer HasAccess() method
		when available. This correctly handles:

		- trial
		- subscribed
		- expired

		The TrialExpired fallback keeps compatibility with
		older User implementations.
	*/
	if !isSuperadmin {
		if user, ok := c.Locals("user").(interface {
			HasAccess() bool
		}); ok {
			if !user.HasAccess() {
				return c.Status(fiber.StatusForbidden).JSON(
					fiber.Map{
						"error": "your trial or subscription is not active. Please subscribe to continue.",
					},
				)
			}
		} else if user, ok := c.Locals("user").(interface {
			TrialExpired() bool
		}); ok && user.TrialExpired() {
			return c.Status(fiber.StatusForbidden).JSON(
				fiber.Map{
					"error": "your free trial has expired. Please subscribe to continue.",
				},
			)
		}
	}

	var input struct {
		PlanID     string `json:"plan_id"`
		Quantity   int    `json:"quantity"`
		Template   string `json:"template"`
		Pattern    string `json:"pattern"`
		CodeLength int    `json:"code_length"`
	}

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	planID, err := uuid.Parse(input.PlanID)
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid plan id",
		)
	}

	generated, err := h.service.GeneratePhysical(
		GenerateInput{
			PlanID:     planID,
			Quantity:   input.Quantity,
			Template:   input.Template,
			Pattern:    input.Pattern,
			CodeLength: input.CodeLength,
		},
		userID,
		isSuperadmin,
	)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.
		Status(fiber.StatusCreated).
		JSON(generated)
}

func (h *Handler) list(c *fiber.Ctx) error {
	userID, isSuperadmin := currentUserScope(c)

	vouchers, err := h.service.List(
		userID,
		isSuperadmin,
	)

	if err != nil {
		return err
	}

	return c.JSON(vouchers)
}

func currentUserScope(
	c *fiber.Ctx,
) (*uuid.UUID, bool) {
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