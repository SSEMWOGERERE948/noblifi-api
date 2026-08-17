package auth

import (
	"errors"
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
	router.Post("/auth/verify-email", h.verifyEmail)
	router.Post("/auth/resend-verification", h.resendVerification)
	router.Post("/auth/login", h.login)
	router.Post("/auth/request-password-reset", h.requestPasswordReset)
	router.Post("/auth/reset-password", h.resetPassword)
	router.Get("/auth/me", h.me)
	router.Get("/users", h.RequireAuth, h.requireSuperadmin, h.users)
	router.Get("/settings/subscription-price", h.RequireAuth, h.requireSuperadmin, h.getSubscriptionPrice)
	router.Put("/settings/subscription-price", h.RequireAuth, h.requireSuperadmin, h.updateSubscriptionPrice)
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
	user, delivery, err := h.service.Signup(input)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyRegistered) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "email is already registered"})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":  verificationMessage(delivery),
		"user":     user,
		"delivery": delivery,
	})
}

func (h *Handler) verifyEmail(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	token, user, err := h.service.VerifyEmail(input.Email, input.Code)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"token": token, "user": user})
}

func (h *Handler) resendVerification(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	delivery, err := h.service.ResendVerification(input.Email)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"message": verificationMessage(delivery), "delivery": delivery})
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

func (h *Handler) requestPasswordReset(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.RequestPasswordReset(input.Email); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not start password reset")
	}
	return c.JSON(fiber.Map{"message": "if the email exists, a reset code has been sent"})
}

func (h *Handler) resetPassword(c *fiber.Ctx) error {
	var input struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.ResetPassword(input.Email, input.Code, input.Password); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"message": "password changed"})
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

func (h *Handler) getSubscriptionPrice(c *fiber.Ctx) error {
	price, err := h.service.SubscriptionPrice()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load subscription price")
	}
	return c.JSON(fiber.Map{"monthly_price_ugx": price})
}

func (h *Handler) updateSubscriptionPrice(c *fiber.Ctx) error {
	var input struct {
		MonthlyPriceUGX int `json:"monthly_price_ugx"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	price, err := h.service.UpdateSubscriptionPrice(input.MonthlyPriceUGX)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not update subscription price")
	}
	return c.JSON(fiber.Map{"monthly_price_ugx": price})
}

func verificationMessage(delivery CodeDelivery) string {
	if delivery.Message != "" {
		return delivery.Message
	}
	if delivery.Sent {
		return "verification code sent"
	}
	return "verification code created"
}
