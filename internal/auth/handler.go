package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/auth/signup", h.signup)
	router.Post("/auth/login", h.login)
	router.Get("/auth/me", h.me)
}

func (h *Handler) signup(c *fiber.Ctx) error {
	var input SignupInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	token, user, err := h.service.Signup(input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"token": token, "user": user})
}

func (h *Handler) login(c *fiber.Ctx) error {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	token, user, err := h.service.Login(input.Email, input.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return c.JSON(fiber.Map{"token": token, "user": user})
}

func (h *Handler) me(c *fiber.Ctx) error {
	token := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if token == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
	}
	user, err := h.service.UserFromToken(token)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return c.JSON(fiber.Map{"user": user})
}
