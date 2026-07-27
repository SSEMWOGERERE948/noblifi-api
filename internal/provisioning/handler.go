package provisioning

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

// RegisterRoutes must be called with the public /api/v1 router, not a router
// that already has the normal user JWT/session middleware attached.
// These endpoints authenticate the MikroTik using its provisioning claim token.
func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/provisioning/check-in", h.checkIn)
	router.Get("/provisioning/check-in", h.checkIn)
	router.Get("/provisioning/bootstrap/:token", h.bootstrap)
	router.Get("/provisioning/install/:token", h.install)
	router.Get("/provisioning/wireguard/:token", h.wireGuard)
	router.Get("/provisioning/hotspot-login/:token", h.hotspotLogin)
	router.Get("/provisioning/interface", h.interfaceCheckIn)
	router.Post("/provisioning/interface", h.interfaceCheckIn)
	router.Get("/provisioning/config.rsc", h.config)
	router.Get("/provisioning/config/:token", h.configByToken)
	router.Post("/provisioning/wireguard-key", h.wireGuardKey)
	router.Post("/provisioning/wireguard-status", h.wireGuardStatus)
	router.Post("/provisioning/status", h.status)
	router.Get("/provisioning/status", h.status)
}

func (h *Handler) wireGuardKey(c *fiber.Ctx) error {
	var input WireGuardKeyInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.WireGuardKey(input); err != nil {
		return provisioningServiceError(err)
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) wireGuardStatus(c *fiber.Ctx) error {
	var input WireGuardStatusInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.WireGuardStatus(input); err != nil {
		return provisioningServiceError(err)
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) bootstrap(c *fiber.Ctx) error {
	script, err := h.service.BootstrapScript(c.Params("token"))
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-bootstrap.rsc"`)
	return c.SendString(script)
}

func (h *Handler) install(c *fiber.Ctx) error {
	script, err := h.service.InstallScript(c.Params("token"), clientIP(c))
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-install.rsc"`)
	return c.SendString(script)
}

func (h *Handler) wireGuard(c *fiber.Ctx) error {
	script, err := h.service.WireGuardScript(c.Params("token"))
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-wireguard.rsc"`)
	return c.SendString(script)
}

func (h *Handler) hotspotLogin(c *fiber.Ctx) error {
	html, err := h.service.HotspotLoginPage(c.Params("token"))
	if err != nil {
		return provisioningServiceError(err)
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
		return provisioningServiceError(err)
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
		return provisioningServiceError(err)
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) config(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(c.Query("token"), c.Query("serial"), clientIP(c))
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="noblifi-config.rsc"`)
	return c.SendString(script)
}

func (h *Handler) configByToken(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(c.Params("token"), "", clientIP(c))
	if err != nil {
		return provisioningServiceError(err)
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
		return provisioningServiceError(err)
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

// provisioningServiceError deliberately returns 403 for invalid/expired
// provisioning claim tokens instead of 401. RouterOS /tool fetch expects a
// WWW-Authenticate challenge on HTTP 401 responses, but these endpoints use a
// query/body provisioning token rather than HTTP Basic/Bearer authentication.
// Returning 403 avoids RouterOS replacing the useful API error with
// "401 should contain www-authenticate header".
func provisioningServiceError(err error) error {
	if err == nil {
		return nil
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(message, "claim token") ||
		strings.Contains(message, "token is required") {
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	}

	if strings.Contains(message, "must be") ||
		strings.Contains(message, "invalid request") {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	return err
}