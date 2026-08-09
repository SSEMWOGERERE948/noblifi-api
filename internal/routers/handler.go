package routers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
)

type Handler struct {
	service *Service
	auth    Authenticator
}

type Authenticator interface {
	UserFromToken(rawToken string) (AuthUser, error)
	VerifyConfirmationCode(user AuthUser, action, code string) error
}

func NewHandler(service *Service, auth ...Authenticator) *Handler {
	handler := &Handler{service: service}
	if len(auth) > 0 {
		handler.auth = auth[0]
	}
	return handler
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/routers", h.create)
	router.Get("/routers", h.list)
	router.Get("/routers/:id", h.get)
	router.Delete("/routers/:id", h.delete)
	router.Post("/routers/:id/regenerate-claim-token", h.regenerateClaimToken)
	router.Post("/routers/:id/setup/remote-access", h.remoteAccess)
	router.Get("/routers/:id/remote-access", h.remoteAccessDetails)
	router.Post("/routers/:id/remote-access/enable", h.enableRemoteAccess)
	router.Post("/routers/:id/test-connection", h.testConnection)
	router.Post("/routers/:id/collect-telemetry", h.collectTelemetry)
	router.Post("/routers/:id/rename", h.renameRouter)
	router.Post("/routers/:id/admin-password", h.updateAdminPassword)
	router.Post("/routers/:id/reboot", h.rebootRouter)
	router.Get("/routers/:id/wireguard", h.wireGuard)
	router.Post("/routers/:id/wireguard/prepare", h.prepareWireGuard)
	router.Post("/routers/:id/setup/method", h.method)
	router.Get("/routers/:id/network-profile", h.networkProfile)
	router.Put("/routers/:id/network-profile", h.updateNetworkProfile)
	router.Get("/routers/:id/interfaces", h.interfaces)
	router.Put("/routers/:id/port-assignments", h.portAssignments)
	router.Get("/routers/:id/bootstrap-script", h.bootstrapScript)
	router.Get("/routers/:id/config-preview", h.configPreview)
	router.Get("/routers/:id/config-install-command", h.configInstallCommand)
	router.Get("/routers/:id/hotspot-install-command", h.hotspotInstallCommand)
	router.Post("/routers/:id/deploy", h.deploy)
	router.Post("/routers/:id/apply-config", h.applyConfig)
	router.Get("/internal/collect-telemetry", h.collectTelemetryAll)
	router.Post("/internal/collect-telemetry", h.collectTelemetryAll)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var input CreateRouterInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if input.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "router name is required")
	}
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	router, err := h.service.CreateForUser(input, user)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(router)
}

func (h *Handler) list(c *fiber.Ctx) error {
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	routers, err := h.service.ListForUser(user)
	if err != nil {
		return err
	}
	return c.JSON(routers)
}

func (h *Handler) get(c *fiber.Ctx) error {
	router, err := h.find(c)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(router)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	user, err := h.requireUser(c)
	if err != nil {
		return err
	}
	var input struct {
		TypedName string `json:"typed_name"`
		Code      string `json:"code"`
	}
	_ = c.BodyParser(&input)
	existing, err := h.authorizeRouter(c, id)
	if err != nil {
		return routerError(err)
	}
	if strings.TrimSpace(input.TypedName) != existing.Name {
		return fiber.NewError(fiber.StatusBadRequest, "router name confirmation does not match")
	}
	if h.auth != nil {
		if err := h.auth.VerifyConfirmationCode(user, "delete_router", input.Code); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
	}
	router, err := h.service.RequestDeleteWithConfirmation(id, user, input.TypedName, input.Code)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(router)
}

func (h *Handler) requireUser(c *fiber.Ctx) (AuthUser, error) {
	if h.auth == nil {
		return AuthUser{}, fiber.NewError(fiber.StatusUnauthorized, "auth service is not configured")
	}
	token := strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if token == "" {
		return AuthUser{}, fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
	}
	user, err := h.auth.UserFromToken(token)
	if err != nil {
		return AuthUser{}, fiber.NewError(fiber.StatusUnauthorized, err.Error())
	}
	return user, nil
}

func (h *Handler) regenerateClaimToken(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	router, err := h.service.RegenerateClaimToken(id)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(router)
}

func (h *Handler) interfaces(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	interfaces, err := h.service.Interfaces(id)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(fiber.Map{"interfaces": interfaces})
}

func (h *Handler) portAssignments(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input struct {
		Assignments []portprofiles.Assignment `json:"assignments"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.SavePortAssignments(id, input.Assignments); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"status": "saved", "assignments": input.Assignments})
}

func (h *Handler) remoteAccess(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input RemoteAccessInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	session, err := h.service.SaveRemoteAccess(id, input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(session)
}

func (h *Handler) remoteAccessDetails(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	details, err := h.service.RemoteAccessDetails(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(details)
}

func (h *Handler) enableRemoteAccess(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	details, err := h.service.EnableVPNRemoteAccess(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(details)
}

func (h *Handler) testConnection(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	result, err := h.service.TestConnection(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadGateway, err.Error())
	}
	return c.JSON(result)
}

func (h *Handler) collectTelemetry(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	telemetry, err := h.service.CollectTelemetry(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadGateway, err.Error())
	}
	return c.JSON(telemetry)
}

func (h *Handler) collectTelemetryAll(c *fiber.Ctx) error {
	if c.Get("X-Appengine-Cron") != "true" {
		return fiber.NewError(fiber.StatusForbidden, "internal endpoint")
	}
	h.service.CollectTelemetryForAllRouters()
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) renameRouter(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	router, err := h.service.RenameRouter(id, input.Name)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(router)
}

func (h *Handler) updateAdminPassword(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.service.UpdateRouterAdminPassword(id, input.Password); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *Handler) rebootRouter(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	if err := h.service.RebootRouter(id); err != nil {
		return fiber.NewError(fiber.StatusBadGateway, err.Error())
	}
	return c.JSON(fiber.Map{"success": true, "message": "router reboot command sent"})
}

func (h *Handler) wireGuard(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	setup, err := h.service.WireGuardSetup(id)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(setup)
}

func (h *Handler) prepareWireGuard(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	setup, err := h.service.PrepareWireGuard(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(setup)
}

func (h *Handler) method(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input MethodInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	session, err := h.service.SaveMethod(id, input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(session)
}

func (h *Handler) networkProfile(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	profile, err := h.service.NetworkProfile(id)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(profile)
}

func (h *Handler) updateNetworkProfile(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	var input RouterNetworkProfile
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	profile, err := h.service.UpdateNetworkProfile(id, input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(profile)
}

func (h *Handler) bootstrapScript(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	script, err := h.service.BootstrapScript(id)
	if err != nil {
		return routerError(err)
	}
	return c.JSON(fiber.Map{"script": script})
}

func (h *Handler) configPreview(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	preview, err := h.service.ConfigPreview(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(preview)
}

func (h *Handler) configInstallCommand(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	command, err := h.service.ConfigInstallCommand(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"script": command})
}

func (h *Handler) hotspotInstallCommand(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	command, err := h.service.HotspotInstallCommand(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"script": command})
}

func (h *Handler) deploy(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	result, err := h.service.Deploy(id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(result)
}

func (h *Handler) applyConfig(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	if _, err := h.authorizeRouter(c, id); err != nil {
		return err
	}
	if _, err := h.service.Deploy(id); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"status": "queued", "message": "Configuration deployment queued"})
}

func (h *Handler) find(c *fiber.Ctx) (Router, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return Router{}, fiber.NewError(fiber.StatusBadRequest, "invalid router id")
	}
	return h.authorizeRouter(c, id)
}

func (h *Handler) authorizeRouter(c *fiber.Ctx, id uuid.UUID) (Router, error) {
	user, err := h.requireUser(c)
	if err != nil {
		return Router{}, err
	}
	router, err := h.service.Find(id)
	if err != nil {
		return router, routerError(err)
	}
	if user.Role != "superadmin" && (router.OwnerUserID == nil || *router.OwnerUserID != user.ID) {
		return router, fiber.NewError(fiber.StatusForbidden, "router does not belong to this account")
	}
	return router, nil
}

func routerError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "router not found")
	}
	return err
}
