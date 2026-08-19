package provisioning

import (
	"strings"

	"github.com/gofiber/fiber/v2"
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
	router.Post(
		"/provisioning/check-in",
		h.checkIn,
	)

	router.Get(
		"/provisioning/check-in",
		h.checkIn,
	)

	router.Get(
		"/provisioning/bootstrap/:token",
		h.bootstrap,
	)

	router.Get(
		"/provisioning/wireguard/:token",
		h.wireGuard,
	)

	router.Get(
		"/provisioning/hotspot-login/:token",
		h.hotspotLogin,
	)

	// The login page posts voucher_code + client MAC here first.
	router.Post(
		"/provisioning/hotspot-auth/:token",
		h.hotspotAuth,
	)

	router.Post(
		"/provisioning/hotspot-auto/:token",
		h.hotspotAutoConnect,
	)

	router.Post(
		"/provisioning/hotspot-buy/:token",
		h.hotspotBuy,
	)

	router.Get(
		"/provisioning/hotspot-buy/:token/:paymentID",
		h.hotspotBuyStatus,
	)

	router.Get(
		"/provisioning/interface",
		h.interfaceCheckIn,
	)

	router.Post(
		"/provisioning/interface",
		h.interfaceCheckIn,
	)

	router.Get(
		"/provisioning/config.rsc",
		h.config,
	)

	router.Get(
		"/provisioning/config/:token",
		h.configByToken,
	)

	router.Post(
		"/provisioning/wireguard-key",
		h.wireGuardKey,
	)

	router.Post(
		"/provisioning/wireguard-status",
		h.wireGuardStatus,
	)

	router.Post(
		"/provisioning/status",
		h.status,
	)

	router.Get(
		"/provisioning/status",
		h.status,
	)
}

func (h *Handler) wireGuardKey(c *fiber.Ctx) error {
	var input WireGuardKeyInput

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	// IMPORTANT:
	//
	// In the service.go supplied by the user WireGuardKey returns ERROR ONLY:
	//
	//	func (s *Service) WireGuardKey(input WireGuardKeyInput) error
	//
	// Do not change this handler to expect two return values.
	if err := h.service.WireGuardKey(input); err != nil {
		return provisioningServiceError(err)
	}

	return c.JSON(
		fiber.Map{
			"status": "ok",
		},
	)
}

func (h *Handler) wireGuardStatus(c *fiber.Ctx) error {
	var input WireGuardStatusInput

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	if err := h.service.WireGuardStatus(input); err != nil {
		return provisioningServiceError(err)
	}

	return c.JSON(
		fiber.Map{
			"status": "ok",
		},
	)
}

func (h *Handler) bootstrap(c *fiber.Ctx) error {
	script, err := h.service.BootstrapScript(
		c.Params("token"),
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextPlainCharsetUTF8,
	)

	c.Set(
		fiber.HeaderContentDisposition,
		`attachment; filename="noblifi-bootstrap.rsc"`,
	)

	return c.SendString(script)
}

func (h *Handler) wireGuard(c *fiber.Ctx) error {
	script, err := h.service.WireGuardScript(
		c.Params("token"),
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextPlainCharsetUTF8,
	)

	c.Set(
		fiber.HeaderContentDisposition,
		`attachment; filename="noblifi-wireguard.rsc"`,
	)

	return c.SendString(script)
}

func (h *Handler) hotspotLogin(c *fiber.Ctx) error {
	pageHTML, err := h.service.HotspotLoginPage(
		c.Params("token"),
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextHTMLCharsetUTF8,
	)

	return c.SendString(pageHTML)
}

func (h *Handler) hotspotAutoConnect(c *fiber.Ctx) error {
	input := HotspotAutoConnectInput{
		MAC:       strings.TrimSpace(c.FormValue("mac")),
		LinkLogin: strings.TrimSpace(c.FormValue("link_login")),
		LinkOrig:  strings.TrimSpace(c.FormValue("link_orig")),
	}

	pageHTML, err := h.service.HotspotAutoConnect(c.Params("token"), input)
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.SendString(pageHTML)
}

func (h *Handler) hotspotAuth(c *fiber.Ctx) error {
	input := HotspotAuthenticateInput{
		VoucherCode: strings.TrimSpace(
			c.FormValue("voucher_code"),
		),

		MAC: strings.TrimSpace(
			c.FormValue("mac"),
		),

		LinkLogin: strings.TrimSpace(
			c.FormValue("link_login"),
		),

		LinkOrig: strings.TrimSpace(
			c.FormValue("link_orig"),
		),
	}

	pageHTML, err := h.service.HotspotAuthenticate(
		c.Params("token"),
		input,
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextHTMLCharsetUTF8,
	)

	return c.SendString(pageHTML)
}

func (h *Handler) checkIn(c *fiber.Ctx) error {
	var input CheckInInput

	if c.Method() == fiber.MethodGet {
		input.ClaimToken = strings.TrimSpace(
			c.Query("token"),
		)

		input.SerialNumber = strings.TrimSpace(
			c.Query("serial"),
		)

		input.Model = strings.TrimSpace(
			c.Query("model"),
		)

		input.RouterOSVersion = strings.TrimSpace(
			c.Query("routeros_version"),
		)
	} else {
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"invalid request body",
			)
		}
	}

	if err := h.service.CheckIn(input); err != nil {
		return provisioningServiceError(err)
	}

	return c.JSON(
		fiber.Map{
			"status": "ok",
		},
	)
}

func (h *Handler) interfaceCheckIn(c *fiber.Ctx) error {
	var input InterfaceCheckInInput

	if c.Method() == fiber.MethodGet {
		input.ClaimToken = strings.TrimSpace(
			c.Query("token"),
		)

		input.Name = strings.TrimSpace(
			c.Query("name"),
		)

		input.Type = strings.TrimSpace(
			c.Query("type"),
		)

		input.MacAddress = strings.TrimSpace(
			c.Query("mac_address"),
		)

		input.Running = strings.TrimSpace(
			c.Query("running"),
		)

		input.Disabled = strings.TrimSpace(
			c.Query("disabled"),
		)
	} else {
		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"invalid request body",
			)
		}
	}

	if err := h.service.InterfaceCheckIn(input); err != nil {
		return provisioningServiceError(err)
	}

	return c.JSON(
		fiber.Map{
			"status": "ok",
		},
	)
}

func (h *Handler) config(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(
		strings.TrimSpace(
			c.Query("token"),
		),

		strings.TrimSpace(
			c.Query("serial"),
		),

		clientIP(c),
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextPlainCharsetUTF8,
	)

	c.Set(
		fiber.HeaderContentDisposition,
		`attachment; filename="noblifi-config.rsc"`,
	)

	return c.SendString(script)
}

func (h *Handler) configByToken(c *fiber.Ctx) error {
	script, err := h.service.ClaimConfig(
		strings.TrimSpace(
			c.Params("token"),
		),
		"",
		clientIP(c),
	)
	if err != nil {
		return provisioningServiceError(err)
	}

	c.Set(
		fiber.HeaderContentType,
		fiber.MIMETextPlainCharsetUTF8,
	)

	c.Set(
		fiber.HeaderContentDisposition,
		`attachment; filename="noblifi-config.rsc"`,
	)

	return c.SendString(script)
}

func (h *Handler) status(c *fiber.Ctx) error {
	token := strings.TrimSpace(
		c.Query("token"),
	)

	serial := strings.TrimSpace(
		c.Query("serial"),
	)

	status := strings.TrimSpace(
		c.Query("status"),
	)

	if token == "" {
		var input struct {
			ClaimToken string `json:"claim_token"`

			Token string `json:"token"`

			SerialNumber string `json:"serial_number"`

			Serial string `json:"serial"`

			Status string `json:"status"`
		}

		if err := c.BodyParser(&input); err != nil {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"invalid request",
			)
		}

		token = strings.TrimSpace(
			input.ClaimToken,
		)

		if token == "" {
			token = strings.TrimSpace(
				input.Token,
			)
		}

		serial = strings.TrimSpace(
			input.SerialNumber,
		)

		if serial == "" {
			serial = strings.TrimSpace(
				input.Serial,
			)
		}

		status = strings.TrimSpace(
			input.Status,
		)
	}

	if err := h.service.Status(
		token,
		serial,
		status,
	); err != nil {
		return provisioningServiceError(err)
	}

	return c.JSON(
		fiber.Map{
			"status": "ok",
		},
	)
}

func clientIP(c *fiber.Ctx) string {
	forwardedFor := strings.TrimSpace(
		c.Get("X-Forwarded-For"),
	)

	if forwardedFor != "" {
		// X-Forwarded-For may contain:
		//
		// client, proxy1, proxy2
		//
		// Only the original client address is needed.
		if comma := strings.Index(
			forwardedFor,
			",",
		); comma >= 0 {
			forwardedFor = strings.TrimSpace(
				forwardedFor[:comma],
			)
		}

		return forwardedFor
	}

	return c.IP()
}

// provisioningServiceError returns 403 for provisioning-token failures.
//
// RouterOS /tool fetch expects WWW-Authenticate on HTTP 401. These routes do
// not use HTTP Basic/Bearer authentication; they use a provisioning claim
// token. Returning 403 preserves the useful API error instead of RouterOS
// replacing it with "401 should contain www-authenticate header".
func provisioningServiceError(err error) error {
	if err == nil {
		return nil
	}

	message := strings.ToLower(
		strings.TrimSpace(
			err.Error(),
		),
	)

	if strings.Contains(
		message,
		"already used",
	) {
		return fiber.NewError(
			fiber.StatusGone,
			err.Error(),
		)
	}

	if strings.Contains(
		message,
		"claim token",
	) ||
		strings.Contains(
			message,
			"provisioning token",
		) ||
		strings.Contains(
			message,
			"session token",
		) ||
		strings.Contains(
			message,
			"token is required",
		) {
		return fiber.NewError(
			fiber.StatusForbidden,
			err.Error(),
		)
	}

	if strings.Contains(
		message,
		"must be",
	) ||
		strings.Contains(
			message,
			"invalid request",
		) ||
		strings.Contains(
			message,
			"invalid public key",
		) ||
		strings.Contains(
			message,
			"interface name is required",
		) ||
		strings.Contains(
			message,
			"return url",
		) {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return err
}