package provisioning

import "github.com/gofiber/fiber/v2"

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/provisioning/check-in", h.checkIn)
	router.Get("/provisioning/check-in", h.checkIn)
	router.Get("/provisioning/bootstrap/:token", h.bootstrap)
	router.Get("/provisioning/config.rsc", h.config)
	router.Post("/provisioning/status", h.status)
	router.Get("/provisioning/status", h.status)
}

func (h *Handler) bootstrap(c *fiber.Ctx) error {
	script, err := h.service.BootstrapScript(c.Params("token"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-bootstrap.rsc"`)
	return c.SendString(script)
}

func (h *Handler) checkIn(c *fiber.Ctx) error {
	var input CheckInInput
	if c.Method() == fiber.MethodGet {
		input.ClaimToken = c.Query("token")
		input.SerialNumber = c.Query("serial")
		input.Model = c.Query("model")
		input.RouterOSVersion = c.Query("routeros_version")
	} else {
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
		}
	}
	if err := h.service.CheckIn(input); err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) config(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(c.Query("token"), c.Query("serial"))
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	return c.SendString(script)
}

func (h *Handler) status(c *fiber.Ctx) error {
	token := c.Query("token")
	serial := c.Query("serial")
	status := c.Query("status")
	if token == "" {
		var input struct {
			ClaimToken   string `json:"claim_token"`
			Token        string `json:"token"`
			SerialNumber string `json:"serial_number"`
			Serial       string `json:"serial"`
			Status       string `json:"status"`
		}
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request")
		}
		token = input.ClaimToken
		if token == "" {
			token = input.Token
		}
		serial = input.SerialNumber
		if serial == "" {
			serial = input.Serial
		}
		status = input.Status
	}
	if err := h.service.Status(token, serial, status); err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return c.JSON(fiber.Map{"status": "ok"})
}
