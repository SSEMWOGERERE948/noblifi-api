package payments

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

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Get("/payments/config", h.config)
	router.Post("/payments/orders", h.startOrder)
	router.Get("/payments/orders/:id/status", h.status)
	router.Get("/payments/pesapal/ipn", h.ipn)
	router.Post("/payments/pesapal/ipn", h.ipn)
}

func (h *Handler) config(c *fiber.Ctx) error {
	return c.JSON(h.service.PublicConfig())
}

func (h *Handler) startOrder(c *fiber.Ctx) error {
	var input StartOrderInput
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	result, err := h.service.StartOrder(input)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	return c.JSON(result)
}

func (h *Handler) status(c *fiber.Ctx) error {
	result, err := h.service.CheckOrder(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(result)
}

func (h *Handler) ipn(c *fiber.Ctx) error {
	trackingID := firstQuery(c, "OrderTrackingId", "orderTrackingId", "order_tracking_id")
	reference := firstQuery(c, "OrderMerchantReference", "orderMerchantReference", "merchantReference", "merchant_reference")

	if c.Method() == fiber.MethodPost {
		var body map[string]string
		if err := c.BodyParser(&body); err == nil {
			if trackingID == "" {
				trackingID = firstMapValue(body, "OrderTrackingId", "orderTrackingId", "order_tracking_id")
			}
			if reference == "" {
				reference = firstMapValue(body, "OrderMerchantReference", "orderMerchantReference", "merchantReference", "merchant_reference")
			}
		}
	}

	result, err := h.service.HandleIPN(trackingID, reference)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(result)
}

func firstQuery(c *fiber.Ctx, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(c.Query(key))
		if value != "" {
			return value
		}
	}
	return ""
}

func firstMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(values[key])
		if value != "" {
			return value
		}
	}
	return ""
}
