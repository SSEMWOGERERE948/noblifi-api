package routers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/routers", h.create)
	router.Get("/routers", h.list)
	router.Get("/routers/:id", h.get)

	router.Post(
		"/routers/:id/regenerate-claim-token",
		h.regenerateClaimToken,
	)

	router.Post(
		"/routers/:id/setup/remote-access",
		h.remoteAccess,
	)

	// The frontend polls this endpoint while WireGuard is being
	// prepared and while waiting for the router/VPS handshake.
	router.Get(
		"/routers/:id/wireguard",
		h.wireGuard,
	)

	router.Post(
		"/routers/:id/setup/method",
		h.method,
	)

	router.Get(
		"/routers/:id/network-profile",
		h.networkProfile,
	)

	router.Put(
		"/routers/:id/network-profile",
		h.updateNetworkProfile,
	)

	router.Get(
		"/routers/:id/interfaces",
		h.interfaces,
	)

	router.Put(
		"/routers/:id/port-assignments",
		h.portAssignments,
	)

	router.Get(
		"/routers/:id/bootstrap-script",
		h.bootstrapScript,
	)

	router.Get(
		"/routers/:id/config-preview",
		h.configPreview,
	)

	router.Get(
		"/routers/:id/config-install-command",
		h.configInstallCommand,
	)

	// Compatibility alias used by the HotSpot setup page.
	router.Get(
		"/routers/:id/hotspot-install-command",
		h.configInstallCommand,
	)

	router.Post(
		"/routers/:id/deploy",
		h.deploy,
	)

	router.Post(
		"/routers/:id/apply-config",
		h.applyConfig,
	)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var input CreateRouterInput

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	if input.Name == "" {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"router name is required",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	router, err := h.service.Create(
		input,
		userID,
		isSuperadmin,
	)
	if err != nil {
		return err
	}

	return c.Status(
		fiber.StatusCreated,
	).JSON(router)
}

func (h *Handler) list(c *fiber.Ctx) error {
	userID, isSuperadmin := currentUserScope(c)

	routers, err := h.service.List(
		userID,
		isSuperadmin,
	)
	if err != nil {
		return err
	}

	return c.JSON(routers)
}

func (h *Handler) get(c *fiber.Ctx) error {
	router, err := h.find(c)

	if err != nil {
		return err
	}

	return c.JSON(router)
}

func (h *Handler) regenerateClaimToken(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	router, err := h.service.RegenerateClaimToken(
		id,
		userID,
		isSuperadmin,
	)
	if err != nil {
		return err
	}

	return c.JSON(router)
}

func (h *Handler) interfaces(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	interfaces, err := h.service.Interfaces(id)

	if err != nil {
		return err
	}

	return c.JSON(
		fiber.Map{
			"interfaces": interfaces,
		},
	)
}

func (h *Handler) portAssignments(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	var input struct {
		Assignments []portprofiles.Assignment `json:"assignments"`
	}

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	if err := h.service.SavePortAssignments(
		id,
		input.Assignments,
		userID,
		isSuperadmin,
	); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(
		fiber.Map{
			"status":      "saved",
			"assignments": input.Assignments,
		},
	)
}

func (h *Handler) remoteAccess(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	var input RemoteAccessInput

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	session, err := h.service.SaveRemoteAccess(
		id,
		input,
		userID,
		isSuperadmin,
	)
	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(session)
}

func (h *Handler) wireGuard(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	// Apply the same router ownership scope as the other
	// authenticated router-management endpoints.
	if _, err := h.service.Find(
		id,
		userID,
		isSuperadmin,
	); err != nil {
		return err
	}

	setup, err := h.service.WireGuardSetup(id)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(setup)
}

func (h *Handler) method(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	var input MethodInput

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	session, err := h.service.SaveMethod(
		id,
		input,
	)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(session)
}

func (h *Handler) networkProfile(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	profile, err := h.service.NetworkProfile(
		id,
		userID,
		isSuperadmin,
	)

	if err != nil {
		return err
	}

	return c.JSON(profile)
}

func (h *Handler) updateNetworkProfile(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	var input RouterNetworkProfile

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid request body",
		)
	}

	userID, isSuperadmin := currentUserScope(c)

	profile, err := h.service.UpdateNetworkProfile(
		id,
		input,
		userID,
		isSuperadmin,
	)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(profile)
}

func (h *Handler) bootstrapScript(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	script, err := h.service.BootstrapScript(id)

	if err != nil {
		return err
	}

	return c.JSON(
		fiber.Map{
			"script": script,
		},
	)
}

func (h *Handler) configPreview(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	preview, err := h.service.ConfigPreview(id)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(preview)
}

func (h *Handler) configInstallCommand(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	command, err := h.service.ConfigInstallCommand(id)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(
		fiber.Map{
			"script": command,
		},
	)
}

func (h *Handler) deploy(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	result, err := h.service.Deploy(id)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(result)
}

func (h *Handler) applyConfig(
	c *fiber.Ctx,
) error {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"invalid router id",
		)
	}

	if _, err := h.service.Deploy(id); err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			err.Error(),
		)
	}

	return c.JSON(
		fiber.Map{
			"status":  "queued",
			"message": "Configuration deployment queued",
		},
	)
}

func (h *Handler) find(
	c *fiber.Ctx,
) (Router, error) {
	id, err := uuid.Parse(c.Params("id"))

	if err != nil {
		return Router{},
			fiber.NewError(
				fiber.StatusBadRequest,
				"invalid router id",
			)
	}

	userID, isSuperadmin := currentUserScope(c)

	return h.service.Find(
		id,
		userID,
		isSuperadmin,
	)
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

	return &id,
		user.GetRole() == "superadmin"
}