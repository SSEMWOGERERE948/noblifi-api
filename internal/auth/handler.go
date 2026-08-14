package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/noblifi/noblifi/backend/internal/database"
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
	router.Get("/users", h.RequireAuth, h.requireSuperadmin, h.users)
}

func (h *Handler) RequireAuth(c *fiber.Ctx) error {
	authHeader := c.Get(fiber.HeaderAuthorization)
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authorization header"})
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid authorization header"})
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing bearer token"})
	}

	user, err := h.service.UserFromToken(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	c.Locals("user", user)
	return c.Next()
}

func (h *Handler) requireSuperadmin(c *fiber.Ctx) error {
	user, ok := c.Locals("user").(database.User)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authenticated user"})
	}
	if user.Role != "superadmin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "superadmin role required"})
	}
	return c.Next()
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
	authHeader := c.Get(fiber.HeaderAuthorization)
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authorization header"})
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid authorization header"})
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	user, err := h.service.UserFromToken(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"user": user})
}

func (h *Handler) users(c *fiber.Ctx) error {
	users, err := h.service.ListUsers()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list users")
	}
	return c.JSON(users)
}
