package provisioning

import (
	"github.com/gofiber/fiber/v2"
	"strings"
)

func (h *Handler) hotspotBuy(c *fiber.Ctx) error {
	var body struct {
		PlanID string `json:"plan_id"`
		Phone  string `json:"phone"`
		Email  string `json:"email"`
		MAC    string `json:"mac"`
	}
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	result, err := h.service.HotspotBuy(c.Params("token"), HotspotBuyInput{PlanID: strings.TrimSpace(body.PlanID), Phone: strings.TrimSpace(body.Phone), Email: strings.TrimSpace(body.Email), DeviceMAC: strings.TrimSpace(body.MAC)})
	if err != nil {
		return provisioningServiceError(err)
	}
	return c.JSON(result)
}

func (h *Handler) hotspotBuyStatus(c *fiber.Ctx) error {
	result, err := h.service.HotspotBuyStatus(c.Params("token"), c.Params("paymentID"), c.Query("mac"))
	if err != nil {
		return provisioningServiceError(err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(result)
}