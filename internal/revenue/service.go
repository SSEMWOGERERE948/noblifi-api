package revenue

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/finance"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

type Scope struct {
	UserID       uuid.UUID
	IsSuperadmin bool
}

type Filters struct {
	RouterID string
	PlanID   string
	Provider string
	Status   string
	From     *time.Time
	To       *time.Time
	Range    string
}

type Summary struct {
	Currency           string `json:"currency"`
	TotalRevenue       int64  `json:"total_revenue"`
	TodayRevenue       int64  `json:"today_revenue"`
	WeekRevenue        int64  `json:"week_revenue"`
	MonthRevenue       int64  `json:"month_revenue"`
	SuccessfulPayments int64  `json:"successful_payments"`
	PendingPayments    int64  `json:"pending_payments"`
	FailedPayments     int64  `json:"failed_payments"`
	PendingValue       int64  `json:"pending_value"`
}

type BreakdownRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Sales    int64  `json:"sales"`
	Revenue  int64  `json:"revenue"`
	Currency string `json:"currency"`
}

type TrendPoint struct {
	Label     string `json:"label"`
	Revenue   int64  `json:"revenue"`
	Purchases int64  `json:"purchases"`
}

type Transaction struct {
	ID                string     `json:"id"`
	TransactionID     string     `json:"transaction_id"`
	Customer          string     `json:"customer"`
	Phone             string     `json:"phone"`
	Hotspot           string     `json:"hotspot"`
	Package           string     `json:"package"`
	Amount            int        `json:"amount"`
	Currency          string     `json:"currency"`
	Provider          string     `json:"provider"`
	PaymentStatus     string     `json:"payment_status"`
	Voucher           string     `json:"voucher"`
	Device            string     `json:"device"`
	ProviderReference string     `json:"provider_reference"`
	MerchantReference string     `json:"merchant_reference"`
	CreatedAt         time.Time  `json:"created_at"`
	PaidAt            *time.Time `json:"paid_at,omitempty"`
}

type AdminPlatformSummary struct {
	Currency             string `json:"currency"`
	OnlineTokenPurchases int64  `json:"online_token_purchases"`
	OnlineTokenGross     int64  `json:"online_token_gross"`
	OnlineTokenFees      int64  `json:"online_token_fees"`
	SubscriptionPayments int64  `json:"subscription_payments"`
	SubscriptionRevenue  int64  `json:"subscription_revenue"`
	TotalPlatformRevenue int64  `json:"total_platform_revenue"`
}

type AdminTokenRevenueRow struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	UserName          string    `json:"user_name"`
	UserEmail         string    `json:"user_email"`
	CustomerName      string    `json:"customer_name"`
	Phone             string    `json:"phone"`
	Package           string    `json:"package"`
	Router            string    `json:"router"`
	GrossAmount       int64     `json:"gross_amount"`
	PlatformFeeAmount int64     `json:"platform_fee_amount"`
	MerchantNetAmount int64     `json:"merchant_net_amount"`
	Currency          string    `json:"currency"`
	PaymentProvider   string    `json:"payment_provider"`
	PaymentReference  string    `json:"payment_reference"`
	SoldAt            time.Time `json:"sold_at"`
}

type AdminSubscriptionRevenueRow struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	UserName          string     `json:"user_name"`
	UserEmail         string     `json:"user_email"`
	Amount            int        `json:"amount"`
	Currency          string     `json:"currency"`
	Provider          string     `json:"provider"`
	Status            string     `json:"status"`
	RawStatus         string     `json:"raw_status"`
	MerchantReference string     `json:"merchant_reference"`
	ProviderReference string     `json:"provider_reference"`
	CreatedAt         time.Time  `json:"created_at"`
	PaidAt            *time.Time `json:"paid_at,omitempty"`
}

type UserAccountSummary struct {
	UserID              string `json:"user_id"`
	UserName            string `json:"user_name"`
	UserEmail           string `json:"user_email"`
	OnlineTokenGross    int64  `json:"online_token_gross"`
	OnlineTokenFees     int64  `json:"online_token_fees"`
	MerchantNetSales    int64  `json:"merchant_net_sales"`
	SubscriptionRevenue int64  `json:"subscription_revenue"`
	WalletCredits       int64  `json:"wallet_credits"`
	WalletDebits        int64  `json:"wallet_debits"`
	WalletAvailable     int64  `json:"wallet_available"`
	PendingWithdrawals  int64  `json:"pending_withdrawals"`
	PaidWithdrawals     int64  `json:"paid_withdrawals"`
	FailedWithdrawals   int64  `json:"failed_withdrawals"`
}

type UserStatement struct {
	UserID    string               `json:"user_id"`
	UserName  string               `json:"user_name"`
	UserEmail string               `json:"user_email"`
	Currency  string               `json:"currency"`
	From      *time.Time           `json:"from,omitempty"`
	To        *time.Time           `json:"to,omitempty"`
	Summary   UserAccountSummary   `json:"summary"`
	Entries   []UserStatementEntry `json:"entries"`
}

type UserStatementEntry struct {
	ID          string    `json:"id"`
	Date        time.Time `json:"date"`
	Source      string    `json:"source"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Debit       int64     `json:"debit"`
	Credit      int64     `json:"credit"`
	Currency    string    `json:"currency"`
	Reference   string    `json:"reference"`
	Provider    string    `json:"provider"`
	Status      string    `json:"status"`
}

func (s *Service) Summary(scope Scope, filters Filters) (Summary, error) {
	now := time.Now()
	todayStart := beginningOfDay(now)
	weekStart := todayStart.AddDate(0, 0, -int(todayStart.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	totalRevenue, err := s.sumPaid(scope, filters, nil, nil)
	if err != nil {
		return Summary{}, err
	}
	todayRevenue, err := s.sumPaid(scope, filters, &todayStart, nil)
	if err != nil {
		return Summary{}, err
	}
	weekRevenue, err := s.sumPaid(scope, filters, &weekStart, nil)
	if err != nil {
		return Summary{}, err
	}
	monthRevenue, err := s.sumPaid(scope, filters, &monthStart, nil)
	if err != nil {
		return Summary{}, err
	}

	successful, err := s.countByStatus(scope, filters, []string{"paid"})
	if err != nil {
		return Summary{}, err
	}
	pending, err := s.countByStatus(scope, filters, []string{"pending", "unpaid", "initiated"})
	if err != nil {
		return Summary{}, err
	}
	failed, err := s.countByStatus(scope, filters, []string{"failed", "cancelled", "expired"})
	if err != nil {
		return Summary{}, err
	}
	pendingValue, err := s.sumByStatus(scope, filters, []string{"pending", "unpaid", "initiated"})
	if err != nil {
		return Summary{}, err
	}

	return Summary{
		Currency: "UGX", TotalRevenue: totalRevenue, TodayRevenue: todayRevenue,
		WeekRevenue: weekRevenue, MonthRevenue: monthRevenue,
		SuccessfulPayments: successful, PendingPayments: pending, FailedPayments: failed,
		PendingValue: pendingValue,
	}, nil
}

func (s *Service) AdminPlatformSummary(scope Scope, filters Filters) (AdminPlatformSummary, error) {
	if !scope.IsSuperadmin {
		return AdminPlatformSummary{}, errors.New("superadmin role required")
	}

	var token struct {
		Count int64
		Gross int64
		Fees  int64
	}
	tokenQuery := s.db.Model(&finance.Sale{}).
		Where("source = ?", finance.SaleSourceMobileMoney)
	tokenQuery = applyDateFilter(tokenQuery, "sold_at", filters)
	if err := tokenQuery.Select("COUNT(*) AS count, COALESCE(SUM(gross_amount), 0) AS gross, COALESCE(SUM(platform_fee_amount), 0) AS fees").Scan(&token).Error; err != nil {
		return AdminPlatformSummary{}, err
	}

	var subscription struct {
		Count int64
		Total int64
	}
	subscriptionQuery := s.db.Model(&payments.PaymentOrder{}).Where("status = ?", "paid")
	subscriptionQuery = applyDateFilter(subscriptionQuery, "updated_at", filters)
	if err := subscriptionQuery.Select("COUNT(*) AS count, COALESCE(SUM(amount), 0) AS total").Scan(&subscription).Error; err != nil {
		return AdminPlatformSummary{}, err
	}

	return AdminPlatformSummary{
		Currency:             "UGX",
		OnlineTokenPurchases: token.Count,
		OnlineTokenGross:     token.Gross,
		OnlineTokenFees:      token.Fees,
		SubscriptionPayments: subscription.Count,
		SubscriptionRevenue:  subscription.Total,
		TotalPlatformRevenue: token.Fees + subscription.Total,
	}, nil
}

func (s *Service) AdminTokenRevenue(scope Scope, filters Filters, limit int) ([]AdminTokenRevenueRow, error) {
	if !scope.IsSuperadmin {
		return nil, errors.New("superadmin role required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var rows []AdminTokenRevenueRow
	query := s.db.Model(&finance.Sale{}).
		Select(`sales.id,
			sales.owner_user_id AS user_id,
			sales.customer_name,
			sales.phone,
			COALESCE(plans.name, '') AS package,
			COALESCE(routers.name, '') AS router,
			sales.gross_amount,
			sales.platform_fee_amount,
			sales.merchant_net_amount,
			sales.currency,
			sales.payment_provider,
			sales.payment_reference,
			sales.sold_at`).
		Joins("LEFT JOIN plans ON plans.id = sales.plan_id").
		Joins("LEFT JOIN routers ON routers.id = sales.router_id").
		Where("sales.source = ?", finance.SaleSourceMobileMoney).
		Order("sales.sold_at DESC").
		Limit(limit)
	query = applyDateFilter(query, "sales.sold_at", filters)
	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}
	if err := s.fillUserDetails(rowsUserIDs(rows), func(id uuid.UUID, user database.User) {
		for index := range rows {
			if rows[index].UserID == id.String() {
				rows[index].UserName = user.Name
				rows[index].UserEmail = user.Email
			}
		}
	}); err != nil {
		return nil, err
	}
	for index := range rows {
		rows[index].Phone = maskPhone(rows[index].Phone)
	}
	return rows, nil
}

func (s *Service) AdminSubscriptionRevenue(scope Scope, filters Filters, limit int) ([]AdminSubscriptionRevenueRow, error) {
	if !scope.IsSuperadmin {
		return nil, errors.New("superadmin role required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var orders []payments.PaymentOrder
	query := s.db.Where("status = ?", "paid").Order("updated_at DESC").Limit(limit)
	query = applyDateFilter(query, "updated_at", filters)
	if err := query.Find(&orders).Error; err != nil {
		return nil, err
	}

	userIDs := make([]uuid.UUID, 0, len(orders))
	orderUserIDs := map[uuid.UUID]uuid.UUID{}
	for _, order := range orders {
		userID, err := uuid.Parse(strings.TrimSpace(order.Email))
		if err != nil {
			continue
		}
		orderUserIDs[order.ID] = userID
		userIDs = append(userIDs, userID)
	}
	users, err := s.usersByID(userIDs)
	if err != nil {
		return nil, err
	}

	rows := make([]AdminSubscriptionRevenueRow, 0, len(orders))
	for _, order := range orders {
		userID := orderUserIDs[order.ID]
		user := users[userID]
		rows = append(rows, AdminSubscriptionRevenueRow{
			ID: order.ID.String(), UserID: userID.String(), UserName: user.Name, UserEmail: user.Email,
			Amount: order.Amount, Currency: order.Currency, Provider: order.Provider, Status: order.Status, RawStatus: order.RawStatus,
			MerchantReference: order.MerchantReference, ProviderReference: order.OrderTrackingID, CreatedAt: order.CreatedAt, PaidAt: paidAtForOrderPtr(order),
		})
	}
	return rows, nil
}

func (s *Service) UserAccountSummaries(scope Scope, filters Filters) ([]UserAccountSummary, error) {
	if !scope.IsSuperadmin {
		return nil, errors.New("superadmin role required")
	}

	var users []database.User
	if err := s.db.Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, err
	}
	rows := make([]UserAccountSummary, 0, len(users))
	for _, user := range users {
		summary, err := s.userAccountSummary(user, filters)
		if err != nil {
			return nil, err
		}
		rows = append(rows, summary)
	}
	return rows, nil
}

func (s *Service) UserStatement(scope Scope, userID uuid.UUID, filters Filters, limit int) (UserStatement, error) {
	if !scope.IsSuperadmin {
		return UserStatement{}, errors.New("superadmin role required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}

	var user database.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return UserStatement{}, err
	}
	summary, err := s.userAccountSummary(user, filters)
	if err != nil {
		return UserStatement{}, err
	}

	entries, err := s.userStatementEntries(user, filters, limit)
	if err != nil {
		return UserStatement{}, err
	}

	return UserStatement{
		UserID: user.ID.String(), UserName: user.Name, UserEmail: user.Email, Currency: "UGX",
		From: filters.From, To: filters.To, Summary: summary, Entries: entries,
	}, nil
}

func (s *Service) ByHotspot(scope Scope, filters Filters) ([]BreakdownRow, error) {
	var rows []BreakdownRow
	err := s.purchases(scope, filters).
		Select("hotspot_purchases.router_id AS id, COALESCE(routers.name, 'Unknown HotSpot') AS name, COUNT(*) AS sales, COALESCE(SUM(hotspot_purchases.amount), 0) AS revenue, COALESCE(MAX(hotspot_purchases.currency), 'UGX') AS currency").
		Joins("LEFT JOIN routers ON routers.id = hotspot_purchases.router_id").
		Where("hotspot_purchases.status = ?", "paid").
		Group("hotspot_purchases.router_id, routers.name").
		Order("revenue DESC").
		Scan(&rows).Error
	return rows, err
}

func (s *Service) ByPackage(scope Scope, filters Filters) ([]BreakdownRow, error) {
	var rows []BreakdownRow
	err := s.purchases(scope, filters).
		Select("hotspot_purchases.plan_id AS id, COALESCE(plans.name, 'Unknown Package') AS name, COUNT(*) AS sales, COALESCE(SUM(hotspot_purchases.amount), 0) AS revenue, COALESCE(MAX(hotspot_purchases.currency), 'UGX') AS currency").
		Joins("LEFT JOIN plans ON plans.id = hotspot_purchases.plan_id").
		Where("hotspot_purchases.status = ?", "paid").
		Group("hotspot_purchases.plan_id, plans.name").
		Order("revenue DESC").
		Scan(&rows).Error
	return rows, err
}

func (s *Service) Trend(scope Scope, filters Filters) ([]TrendPoint, error) {
	start, end, bucket := trendRange(filters.Range, filters.From, filters.To)
	var purchases []payments.HotspotPurchase
	if err := s.purchases(scope, filters).
		Where("status = ?", "paid").
		Where("COALESCE(paid_at, created_at) >= ? AND COALESCE(paid_at, created_at) < ?", start, end).
		Find(&purchases).Error; err != nil {
		return nil, err
	}

	type aggregate struct {
		revenue   int64
		purchases int64
	}
	points := map[time.Time]aggregate{}
	for cursor := start; cursor.Before(end); cursor = addBucket(cursor, bucket) {
		points[cursor] = aggregate{}
	}
	for _, purchase := range purchases {
		at := purchase.CreatedAt
		if purchase.PaidAt != nil {
			at = *purchase.PaidAt
		}
		key := bucketStart(at, bucket)
		item := points[key]
		item.revenue += int64(purchase.Amount)
		item.purchases++
		points[key] = item
	}

	result := make([]TrendPoint, 0, len(points))
	for cursor := start; cursor.Before(end); cursor = addBucket(cursor, bucket) {
		item := points[cursor]
		result = append(result, TrendPoint{
			Label: labelFor(cursor, bucket), Revenue: item.revenue, Purchases: item.purchases,
		})
	}
	return result, nil
}

func (s *Service) Transactions(scope Scope, filters Filters, limit int) ([]Transaction, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var rows []Transaction
	err := s.purchases(scope, filters).
		Select(`hotspot_purchases.id,
			COALESCE(hotspot_purchases.local_transaction_id, '') AS transaction_id,
			COALESCE(NULLIF(hotspot_purchases.customer_name, ''), hotspot_purchases.email, '') AS customer,
			hotspot_purchases.phone,
			COALESCE(routers.name, 'Unknown HotSpot') AS hotspot,
			COALESCE(plans.name, 'Unknown Package') AS package,
			hotspot_purchases.amount,
			hotspot_purchases.currency,
			hotspot_purchases.provider,
			hotspot_purchases.status AS payment_status,
			COALESCE(vouchers.code, '') AS voucher,
			hotspot_purchases.device_mac AS device,
			hotspot_purchases.order_tracking_id AS provider_reference,
			hotspot_purchases.merchant_reference,
			hotspot_purchases.created_at,
			hotspot_purchases.paid_at`).
		Joins("LEFT JOIN routers ON routers.id = hotspot_purchases.router_id").
		Joins("LEFT JOIN plans ON plans.id = hotspot_purchases.plan_id").
		Joins("LEFT JOIN vouchers ON vouchers.id = hotspot_purchases.voucher_id").
		Order("hotspot_purchases.created_at DESC").
		Limit(limit).
		Scan(&rows).Error
	for index := range rows {
		rows[index].Phone = maskPhone(rows[index].Phone)
	}
	return rows, err
}

func (s *Service) RouterSummary(scope Scope, routerID uuid.UUID) (Summary, error) {
	query := s.db.Model(&routers.Router{}).Where("id = ?", routerID)
	if !scope.IsSuperadmin {
		query = query.Where("user_id = ?", scope.UserID)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return Summary{}, err
	}
	if count == 0 {
		return Summary{}, gorm.ErrRecordNotFound
	}
	filters := Filters{RouterID: routerID.String()}
	return s.Summary(scope, filters)
}

func (s *Service) sumPaid(scope Scope, filters Filters, from *time.Time, to *time.Time) (int64, error) {
	return s.sumByStatusWithDates(scope, filters, []string{"paid"}, from, to)
}

func (s *Service) sumByStatus(scope Scope, filters Filters, statuses []string) (int64, error) {
	return s.sumByStatusWithDates(scope, filters, statuses, nil, nil)
}

func (s *Service) sumByStatusWithDates(scope Scope, filters Filters, statuses []string, from *time.Time, to *time.Time) (int64, error) {
	var out struct{ Total int64 }
	query := s.purchases(scope, filters).Select("COALESCE(SUM(amount), 0) AS total").Where("status IN ?", statuses)
	if from != nil {
		query = query.Where("COALESCE(paid_at, created_at) >= ?", *from)
	}
	if to != nil {
		query = query.Where("COALESCE(paid_at, created_at) < ?", *to)
	}
	err := query.Scan(&out).Error
	return out.Total, err
}

func (s *Service) countByStatus(scope Scope, filters Filters, statuses []string) (int64, error) {
	var count int64
	err := s.purchases(scope, filters).Where("status IN ?", statuses).Count(&count).Error
	return count, err
}

func (s *Service) purchases(scope Scope, filters Filters) *gorm.DB {
	query := s.db.Model(&payments.HotspotPurchase{})
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}
	if filters.RouterID != "" {
		query = query.Where("router_id = ?", filters.RouterID)
	}
	if filters.PlanID != "" {
		query = query.Where("plan_id = ?", filters.PlanID)
	}
	if filters.Provider != "" {
		query = query.Where("LOWER(provider) = ?", strings.ToLower(filters.Provider))
	}
	if filters.Status != "" {
		query = query.Where("status = ?", strings.ToLower(filters.Status))
	}
	if filters.From != nil {
		query = query.Where("COALESCE(paid_at, created_at) >= ?", *filters.From)
	}
	if filters.To != nil {
		query = query.Where("COALESCE(paid_at, created_at) < ?", *filters.To)
	}
	return query
}

func (s *Service) userAccountSummary(user database.User, filters Filters) (UserAccountSummary, error) {
	var sales struct {
		Gross int64
		Fees  int64
		Net   int64
	}
	salesQuery := s.db.Model(&finance.Sale{}).Where("owner_user_id = ?", user.ID)
	salesQuery = applyDateFilter(salesQuery, "sold_at", filters)
	if err := salesQuery.Select("COALESCE(SUM(gross_amount), 0) AS gross, COALESCE(SUM(platform_fee_amount), 0) AS fees, COALESCE(SUM(merchant_net_amount), 0) AS net").Scan(&sales).Error; err != nil {
		return UserAccountSummary{}, err
	}

	var walletCredits, walletDebits int64
	ledgerQuery := s.db.Model(&finance.WalletTransaction{}).Where("owner_user_id = ?", user.ID)
	ledgerQuery = applyDateFilter(ledgerQuery, "created_at", filters)
	if err := ledgerQuery.Where("direction = ?", finance.LedgerDirectionCredit).Select("COALESCE(SUM(amount), 0)").Scan(&walletCredits).Error; err != nil {
		return UserAccountSummary{}, err
	}
	ledgerQuery = s.db.Model(&finance.WalletTransaction{}).Where("owner_user_id = ?", user.ID)
	ledgerQuery = applyDateFilter(ledgerQuery, "created_at", filters)
	if err := ledgerQuery.Where("direction = ?", finance.LedgerDirectionDebit).Select("COALESCE(SUM(amount), 0)").Scan(&walletDebits).Error; err != nil {
		return UserAccountSummary{}, err
	}

	var pendingWithdrawals, paidWithdrawals, failedWithdrawals int64
	withdrawalQuery := s.db.Model(&finance.Withdrawal{}).Where("owner_user_id = ?", user.ID)
	withdrawalQuery = applyDateFilter(withdrawalQuery, "created_at", filters)
	_ = withdrawalQuery.Where("status IN ?", []string{finance.WithdrawalStatusRequested, finance.WithdrawalStatusProcessing, finance.WithdrawalStatusPending}).Select("COALESCE(SUM(amount), 0)").Scan(&pendingWithdrawals).Error
	withdrawalQuery = s.db.Model(&finance.Withdrawal{}).Where("owner_user_id = ?", user.ID)
	withdrawalQuery = applyDateFilter(withdrawalQuery, "created_at", filters)
	_ = withdrawalQuery.Where("status = ?", finance.WithdrawalStatusPaid).Select("COALESCE(SUM(amount), 0)").Scan(&paidWithdrawals).Error
	withdrawalQuery = s.db.Model(&finance.Withdrawal{}).Where("owner_user_id = ?", user.ID)
	withdrawalQuery = applyDateFilter(withdrawalQuery, "created_at", filters)
	_ = withdrawalQuery.Where("status = ?", finance.WithdrawalStatusFailed).Select("COALESCE(SUM(amount), 0)").Scan(&failedWithdrawals).Error

	subscriptionRevenue, err := s.subscriptionRevenueForUser(user.ID, filters)
	if err != nil {
		return UserAccountSummary{}, err
	}

	return UserAccountSummary{
		UserID: user.ID.String(), UserName: user.Name, UserEmail: user.Email,
		OnlineTokenGross: sales.Gross, OnlineTokenFees: sales.Fees, MerchantNetSales: sales.Net,
		SubscriptionRevenue: subscriptionRevenue, WalletCredits: walletCredits, WalletDebits: walletDebits,
		WalletAvailable: walletCredits - walletDebits, PendingWithdrawals: pendingWithdrawals,
		PaidWithdrawals: paidWithdrawals, FailedWithdrawals: failedWithdrawals,
	}, nil
}

func (s *Service) subscriptionRevenueForUser(userID uuid.UUID, filters Filters) (int64, error) {
	var total int64
	query := s.db.Model(&payments.PaymentOrder{}).Where("status = ? AND email = ?", "paid", userID.String())
	query = applyDateFilter(query, "updated_at", filters)
	err := query.Select("COALESCE(SUM(amount), 0)").Scan(&total).Error
	return total, err
}

func (s *Service) userStatementEntries(user database.User, filters Filters, limit int) ([]UserStatementEntry, error) {
	entries := make([]UserStatementEntry, 0)

	var ledger []finance.WalletTransaction
	ledgerQuery := s.db.Where("owner_user_id = ?", user.ID).Order("created_at DESC").Limit(limit)
	ledgerQuery = applyDateFilter(ledgerQuery, "created_at", filters)
	if err := ledgerQuery.Find(&ledger).Error; err != nil {
		return nil, err
	}
	for _, row := range ledger {
		entry := UserStatementEntry{
			ID: row.ID.String(), Date: row.CreatedAt, Source: "wallet_ledger", Type: row.Type, Description: row.Description,
			Currency: row.Currency, Reference: referenceString(row.ReferenceType, row.ReferenceID), Status: "posted",
		}
		if row.Direction == finance.LedgerDirectionDebit {
			entry.Debit = row.Amount
		} else {
			entry.Credit = row.Amount
		}
		entries = append(entries, entry)
	}

	var subscriptions []payments.PaymentOrder
	subscriptionQuery := s.db.Where("status = ? AND email = ?", "paid", user.ID.String()).Order("updated_at DESC").Limit(limit)
	subscriptionQuery = applyDateFilter(subscriptionQuery, "updated_at", filters)
	if err := subscriptionQuery.Find(&subscriptions).Error; err != nil {
		return nil, err
	}
	for _, row := range subscriptions {
		entries = append(entries, UserStatementEntry{
			ID: row.ID.String(), Date: paidAtForOrder(row), Source: "subscription", Type: "subscription_payment",
			Description: "NobliFi subscription payment", Debit: int64(row.Amount), Currency: row.Currency,
			Reference: row.MerchantReference, Provider: row.Provider, Status: row.Status,
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Date.After(entries[j].Date)
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func applyDateFilter(query *gorm.DB, column string, filters Filters) *gorm.DB {
	if filters.From != nil {
		query = query.Where(column+" >= ?", *filters.From)
	}
	if filters.To != nil {
		query = query.Where(column+" < ?", filters.To.Add(24*time.Hour))
	}
	return query
}

func (s *Service) usersByID(ids []uuid.UUID) (map[uuid.UUID]database.User, error) {
	out := map[uuid.UUID]database.User{}
	if len(ids) == 0 {
		return out, nil
	}
	var users []database.User
	if err := s.db.Where("id IN ?", uniqueUUIDs(ids)).Find(&users).Error; err != nil {
		return nil, err
	}
	for _, user := range users {
		out[user.ID] = user
	}
	return out, nil
}

func (s *Service) fillUserDetails(ids []uuid.UUID, apply func(uuid.UUID, database.User)) error {
	users, err := s.usersByID(ids)
	if err != nil {
		return err
	}
	for id, user := range users {
		apply(id, user)
	}
	return nil
}

func rowsUserIDs(rows []AdminTokenRevenueRow) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		id, err := uuid.Parse(row.UserID)
		if err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func uniqueUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func paidAtForOrder(order payments.PaymentOrder) time.Time {
	if !order.UpdatedAt.IsZero() {
		return order.UpdatedAt
	}
	return order.CreatedAt
}

func paidAtForOrderPtr(order payments.PaymentOrder) *time.Time {
	paidAt := paidAtForOrder(order)
	return &paidAt
}

func referenceString(referenceType string, referenceID *uuid.UUID) string {
	if referenceID == nil {
		return strings.TrimSpace(referenceType)
	}
	return strings.TrimSpace(referenceType) + ":" + referenceID.String()
}

func beginningOfDay(value time.Time) time.Time {
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, value.Location())
}

func trendRange(raw string, from *time.Time, to *time.Time) (time.Time, time.Time, string) {
	now := time.Now()
	rangeName := strings.ToLower(strings.TrimSpace(raw))
	if from != nil && to != nil {
		return beginningOfDay(*from), to.Add(24 * time.Hour), "day"
	}
	switch rangeName {
	case "today":
		return beginningOfDay(now), beginningOfDay(now).Add(24 * time.Hour), "hour"
	case "30d", "30days", "30 days":
		return beginningOfDay(now).AddDate(0, 0, -29), beginningOfDay(now).Add(24 * time.Hour), "day"
	case "3m", "3 months":
		return beginningOfDay(now).AddDate(0, -3, 0), beginningOfDay(now).Add(24 * time.Hour), "week"
	case "6m", "6 months":
		return beginningOfDay(now).AddDate(0, -6, 0), beginningOfDay(now).Add(24 * time.Hour), "week"
	case "this_month":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()), beginningOfDay(now).Add(24 * time.Hour), "day"
	case "this_year":
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location()), beginningOfDay(now).Add(24 * time.Hour), "month"
	default:
		return beginningOfDay(now).AddDate(0, 0, -6), beginningOfDay(now).Add(24 * time.Hour), "day"
	}
}

func bucketStart(value time.Time, bucket string) time.Time {
	switch bucket {
	case "hour":
		return time.Date(value.Year(), value.Month(), value.Day(), value.Hour(), 0, 0, 0, value.Location())
	case "week":
		day := beginningOfDay(value)
		return day.AddDate(0, 0, -int(day.Weekday()))
	case "month":
		return time.Date(value.Year(), value.Month(), 1, 0, 0, 0, 0, value.Location())
	default:
		return beginningOfDay(value)
	}
}

func addBucket(value time.Time, bucket string) time.Time {
	switch bucket {
	case "hour":
		return value.Add(time.Hour)
	case "week":
		return value.AddDate(0, 0, 7)
	case "month":
		return value.AddDate(0, 1, 0)
	default:
		return value.AddDate(0, 0, 1)
	}
}

func labelFor(value time.Time, bucket string) string {
	switch bucket {
	case "hour":
		return value.Format("15:00")
	case "month":
		return value.Format("Jan")
	default:
		return value.Format("Jan 2")
	}
}

func maskPhone(phone string) string {
	phone = strings.TrimSpace(phone)
	if len(phone) <= 4 {
		return phone
	}
	prefix := phone
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return prefix + "..." + phone[len(phone)-3:]
}
