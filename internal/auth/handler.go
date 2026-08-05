package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	router.Put("/account/profile", h.updateProfile)
	router.Post("/auth/change-password", h.changePassword)
	router.Get("/admin/users", h.users)
	router.Get("/admin/users/account-details", h.accountDetails)
	router.Post("/admin/users/:id/approve", h.approveUser)
	router.Post("/account/router-limit-requests", h.requestRouterLimit)
	router.Get("/admin/router-limit-requests", h.routerLimitRequests)
	router.Post("/admin/router-limit-requests/:id/decide", h.decideRouterLimitRequest)
	router.Post("/auth/confirmation-codes", h.createConfirmationCode)
}

func (h *Handler) signup(c *fiber.Ctx) error {
	var input SignupInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	user, err := h.service.Signup(input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user":    user,
		"message": "Account created. A superadmin must approve it before login.",
	})
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

func (h *Handler) changePassword(c *fiber.Ctx) error {
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.ChangePassword(user, input.CurrentPassword, input.NewPassword); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *Handler) updateProfile(c *fiber.Ctx) error {
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	var input struct {
		PortalName string `json:"portal_name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	updated, err := h.service.UpdateAccountProfile(user, input.PortalName)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"user": updated})
}

func (h *Handler) users(c *fiber.Ctx) error {
	if _, err := h.requireRole(c, "superadmin"); err != nil {
		return err
	}
	users, err := h.service.Users()
	if err != nil {
		return err
	}
	return c.JSON(users)
}

func (h *Handler) accountDetails(c *fiber.Ctx) error {
	if _, err := h.requireRole(c, "superadmin"); err != nil {
		return err
	}
	username := c.Query("username")
	if username == "" {
		username = c.Query("email")
	}
	details, err := h.service.AccountDetailsByUsername(username)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return c.JSON(details)
}

func (h *Handler) approveUser(c *fiber.Ctx) error {
	if _, err := h.requireRole(c, "superadmin"); err != nil {
		return err
	}
	userID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid user id")
	}
	var input struct {
		RouterLimit int `json:"router_limit"`
	}
	_ = c.BodyParser(&input)
	user, err := h.service.ApproveUser(userID, input.RouterLimit)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(user)
}

func (h *Handler) requestRouterLimit(c *fiber.Ctx) error {
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	var input struct {
		RequestedLimit int    `json:"requested_limit"`
		Reason         string `json:"reason"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	request, err := h.service.RequestRouterLimit(user, input.RequestedLimit, input.Reason)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(request)
}

func (h *Handler) routerLimitRequests(c *fiber.Ctx) error {
	if _, err := h.requireRole(c, "superadmin"); err != nil {
		return err
	}
	requests, err := h.service.RouterLimitRequests()
	if err != nil {
		return err
	}
	return c.JSON(requests)
}

func (h *Handler) decideRouterLimitRequest(c *fiber.Ctx) error {
	admin, err := h.requireRole(c, "superadmin")
	if err != nil {
		return err
	}
	requestID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request id")
	}
	var input struct {
		Approved bool `json:"approved"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	request, err := h.service.DecideRouterLimitRequest(requestID, admin.ID, input.Approved)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(request)
}

func (h *Handler) createConfirmationCode(c *fiber.Ctx) error {
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	var input struct {
		Action string `json:"action"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	confirmation, code, err := h.service.CreateConfirmationCode(user, input.Action)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	// TODO: wire SMTP/provider delivery. Until then this appears in API logs
	// and dev responses so the confirmation flow can be tested end-to-end.
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":         confirmation.ID,
		"expires_at": confirmation.ExpiresAt,
		"message":    "Confirmation code created. Configure email delivery before production.",
		"dev_code":   code,
	})
}

func (h *Handler) requireRole(c *fiber.Ctx, role string) (database.User, error) {
	user, err := h.requireUser(c)
	if err != nil {
		return user, err
	}
	if user.Role != role {
		return user, fiber.NewError(fiber.StatusForbidden, "insufficient permissions")
	}
	return user, nil
}

func (h *Handler) requireUser(c *fiber.Ctx) (database.User, error) {
	token := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if token == "" {
		return database.User{}, fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
	}
	user, err := h.service.UserFromToken(token)
	if err != nil {
		return database.User{}, fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return user, nil
}
