package wireguard

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	internal := router.Group("/internal", h.auth)
	internal.Post("/agents/register", h.heartbeat)
	internal.Post("/agents/heartbeat", h.heartbeat)
	internal.Post("/wireguard/jobs/claim", h.claim)
	internal.Post("/wireguard/jobs/:id/applying", h.applying)
	internal.Post("/wireguard/jobs/:id/complete", h.complete)
	internal.Post("/wireguard/jobs/:id/fail", h.fail)
	internal.Post("/wireguard/reconcile/report", h.reconcileReport)
}

func (h *Handler) auth(c *fiber.Ctx) error {
	if !h.service.AuthenticateAgent(c.Get(fiber.HeaderAuthorization)) {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}
	return c.Next()
}

type heartbeatInput struct {
	AgentID            string     `json:"agent_id"`
	Version            string     `json:"version"`
	WireGuardInterface string     `json:"wireguard_interface"`
	PeerCount          int        `json:"peer_count"`
	Healthy            bool       `json:"healthy"`
	LastReconciliation *time.Time `json:"last_reconciliation"`
}

func (h *Handler) heartbeat(c *fiber.Ctx) error {
	var input heartbeatInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if input.AgentID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "agent_id is required")
	}
	if err := h.service.Heartbeat(input.AgentID, input.Version, input.WireGuardInterface, input.PeerCount, input.Healthy, input.LastReconciliation); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

type claimInput struct {
	AgentID      string `json:"agent_id"`
	LeaseSeconds int    `json:"lease_seconds"`
}

func (h *Handler) claim(c *fiber.Ctx) error {
	var input claimInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if input.AgentID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "agent_id is required")
	}
	lease := time.Duration(input.LeaseSeconds) * time.Second
	job, ok, err := h.service.ClaimJob(input.AgentID, lease)
	if err != nil {
		return err
	}
	if !ok {
		return c.JSON(fiber.Map{"status": "empty"})
	}
	return c.JSON(fiber.Map{"status": "claimed", "job": job})
}

func (h *Handler) applying(c *fiber.Ctx) error {
	id, agentID, err := jobRequest(c)
	if err != nil {
		return err
	}
	if err := h.service.MarkApplying(id, agentID); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) complete(c *fiber.Ctx) error {
	id, agentID, err := jobRequest(c)
	if err != nil {
		return err
	}
	if err := h.service.CompleteJob(id, agentID); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) fail(c *fiber.Ctx) error {
	id, agentID, err := jobRequest(c)
	if err != nil {
		return err
	}
	var input struct {
		Error string `json:"error"`
	}
	_ = c.BodyParser(&input)
	if err := h.service.FailJob(id, agentID, input.Error); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) reconcileReport(c *fiber.Ctx) error {
	var input heartbeatInput
	_ = c.BodyParser(&input)
	if input.AgentID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "agent_id is required")
	}
	now := time.Now().UTC()
	if input.LastReconciliation == nil {
		input.LastReconciliation = &now
	}
	if err := h.service.Heartbeat(input.AgentID, input.Version, input.WireGuardInterface, input.PeerCount, input.Healthy, input.LastReconciliation); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

func jobRequest(c *fiber.Ctx) (uuid.UUID, string, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, "", fiber.NewError(fiber.StatusBadRequest, "invalid job id")
	}
	var input struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return uuid.Nil, "", fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if input.AgentID == "" {
		return uuid.Nil, "", fiber.NewError(fiber.StatusBadRequest, "agent_id is required")
	}
	return id, input.AgentID, nil
}
