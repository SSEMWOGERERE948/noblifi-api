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
	router.Get("/provisioning/hotspot-login/:token", h.hotspotLogin)
	router.Get("/provisioning/interface", h.interfaceCheckIn)
	router.Post("/provisioning/interface", h.interfaceCheckIn)
	router.Get("/provisioning/config.rsc", h.config)
	router.Get("/provisioning/config/:token", h.configByToken)
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

func (h *Handler) hotspotLogin(c *fiber.Ctx) error {
	html, err := h.service.HotspotLoginPage(c.Params("token"))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.SendString(html)
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

func (h *Handler) interfaceCheckIn(c *fiber.Ctx) error {
	var input InterfaceCheckInInput
	if c.Method() == fiber.MethodGet {
		input.ClaimToken = c.Query("token")
		input.Name = c.Query("name")
		input.Type = c.Query("type")
		input.MacAddress = c.Query("mac_address")
		input.Running = c.Query("running")
		input.Disabled = c.Query("disabled")
	} else {
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
		}
	}
	if err := h.service.InterfaceCheckIn(input); err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) config(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(c.Query("token"), c.Query("serial"), clientIP(c))
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-config.rsc"`)
	return c.SendString(script)
}

func (h *Handler) configByToken(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(c.Params("token"), "", clientIP(c))
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-config.rsc"`)
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

func clientIP(c *fiber.Ctx) string {
	forwardedFor := c.Get("X-Forwarded-For")
	if forwardedFor != "" {
		return forwardedFor
	}
	return c.IP()
}
