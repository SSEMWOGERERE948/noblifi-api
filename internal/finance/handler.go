package finance

import (
	"strconv"
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
	router.Get("/sales", h.sales)
	router.Get("/sales/summary", h.salesSummary)
	router.Post("/vouchers/:id/record-sale", h.recordPhysicalSale)

	router.Get("/wallet", h.wallet)
	router.Get("/wallet/transactions", h.walletTransactions)
	router.Get("/wallet/withdrawals", h.withdrawals)
	router.Get("/wallet/withdrawals/:id/status", h.withdrawalStatus)
	router.Get("/wallet/withdraw/recipient", h.withdrawRecipient)
	router.Post("/wallet/withdraw/code", h.withdrawCode)
	router.Post("/wallet/withdraw", h.withdraw)

	router.Get("/admin/finance/summary", h.adminSummary)
	router.Get("/admin/finance/platform-wallet", h.platformWallet)
	router.Post("/admin/finance/platform-wallet/withdraw", h.platformWithdraw)
	router.Get("/admin/finance/commissions", h.commissions)
	router.Get("/admin/finance/withdrawals", h.adminWithdrawals)
}

func (h *Handler) sales(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	rows, err := h.service.Sales(scope(c), limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load sales")
	}
	return c.JSON(rows)
}

func (h *Handler) salesSummary(c *fiber.Ctx) error {
	out, err := h.service.SalesSummary(scope(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load sales summary")
	}
	return c.JSON(out)
}

func (h *Handler) recordPhysicalSale(c *fiber.Ctx) error {
	voucherID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid voucher id")
	}
	var body struct {
		Amount       int64  `json:"amount"`
		CustomerName string `json:"customer_name"`
		Phone        string `json:"phone"`
		RouterID     string `json:"router_id"`
	}
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	var routerID *uuid.UUID
	if strings.TrimSpace(body.RouterID) != "" {
		parsed, err := uuid.Parse(strings.TrimSpace(body.RouterID))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid router id")
		}
		routerID = &parsed
	}
	sc := scope(c)
	sale, err := h.service.RecordPhysicalSale(sc, RecordPhysicalSaleInput{
		VoucherID: voucherID, Amount: body.Amount, CustomerName: body.CustomerName,
		Phone: body.Phone, RouterID: routerID, CreatedByUserID: sc.UserID,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(sale)
}

func (h *Handler) wallet(c *fiber.Ctx) error {
	out, err := h.service.WalletSummary(scope(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load wallet")
	}
	return c.JSON(out)
}

func (h *Handler) walletTransactions(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	out, err := h.service.WalletTransactions(scope(c), limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load wallet transactions")
	}
	return c.JSON(out)
}

func (h *Handler) withdrawals(c *fiber.Ctx) error {
	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	rows, err := h.service.Withdrawals(scope(c), limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load withdrawals")
	}
	return c.JSON(rows)
}

func (h *Handler) withdrawalStatus(c *fiber.Ctx) error {
	withdrawalID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid withdrawal id")
	}
	out, err := h.service.RefreshWithdrawalStatus(scope(c), withdrawalID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "record not found") {
			return fiber.NewError(fiber.StatusNotFound, "withdrawal not found")
		}
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(out)
}

func (h *Handler) withdrawRecipient(c *fiber.Ctx) error {
	out, err := h.service.LookupWithdrawalRecipient(scope(c), c.Query("destination"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(out)
}

func (h *Handler) withdrawCode(c *fiber.Ctx) error {
	var body struct {
		Amount      int64  `json:"amount"`
		Destination string `json:"destination"`
	}
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	user, _ := c.Locals("user").(database.User)
	out, err := h.service.RequestWithdrawalCode(scope(c), user, body.Amount, body.Destination)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(out)
}

func (h *Handler) withdraw(c *fiber.Ctx) error {
	var body struct {
		Amount      int64  `json:"amount"`
		Destination string `json:"destination"`
		Code        string `json:"code"`
	}
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	user, _ := c.Locals("user").(database.User)
	out, err := h.service.ConfirmWithdrawal(scope(c), user, body.Amount, body.Destination, body.Code)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) adminSummary(c *fiber.Ctx) error {
	out, err := h.service.AdminFinanceSummary(scope(c))
	if err != nil {
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	}
	return c.JSON(out)
}

func (h *Handler) platformWallet(c *fiber.Ctx) error {
	sc := scope(c)
	if !sc.IsSuperadmin {
		return fiber.NewError(fiber.StatusForbidden, "superadmin role required")
	}
	wallet, err := h.service.platformWallet(h.service.db, "UGX")
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load platform wallet")
	}
	summary, _ := h.service.walletSummary(wallet.ID, wallet.Currency)
	return c.JSON(summary)
}

func (h *Handler) commissions(c *fiber.Ctx) error {
	sc := scope(c)
	if !sc.IsSuperadmin {
		return fiber.NewError(fiber.StatusForbidden, "superadmin role required")
	}
	var rows []WalletTransaction
	err := h.service.db.Where("type = ?", LedgerTypePlatformCommission).Order("created_at desc").Limit(100).Find(&rows).Error
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load commissions")
	}
	return c.JSON(rows)
}

func (h *Handler) platformWithdraw(c *fiber.Ctx) error {
	var body struct {
		Amount      int64  `json:"amount"`
		Destination string `json:"destination"`
	}
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	user, _ := c.Locals("user").(database.User)
	out, err := h.service.RequestPlatformWithdrawal(scope(c), user, body.Amount, body.Destination)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) adminWithdrawals(c *fiber.Ctx) error {
	sc := scope(c)
	if !sc.IsSuperadmin {
		return fiber.NewError(fiber.StatusForbidden, "superadmin role required")
	}
	var rows []Withdrawal
	query := h.service.db.Order("created_at desc").Limit(100)
	if walletType := strings.TrimSpace(c.Query("wallet_type")); walletType != "" {
		query = query.Where("wallet_type = ?", walletType)
	}
	err := query.Find(&rows).Error
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not load withdrawals")
	}
	return c.JSON(rows)
}

func scope(c *fiber.Ctx) Scope {
	user, _ := c.Locals("user").(database.User)
	return Scope{UserID: user.ID, IsSuperadmin: user.Role == "superadmin"}
}
