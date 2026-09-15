package finance

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	SaleSourceMobileMoney = "mobile_money"
	SaleSourcePhysical    = "physical"

	WalletTypeMerchant = "merchant"
	WalletTypePlatform = "platform"

	LedgerTypeSaleCredit         = "sale_credit"
	LedgerTypePlatformCommission = "platform_commission"
	LedgerTypeWithdrawalReserve  = "withdrawal_reserve"
	LedgerTypeWithdrawalPaid     = "withdrawal_paid"
	LedgerTypeWithdrawalRelease  = "withdrawal_release"
	LedgerTypeAdjustment         = "adjustment"

	LedgerDirectionCredit = "credit"
	LedgerDirectionDebit  = "debit"

	WithdrawalStatusRequested  = "requested"
	WithdrawalStatusProcessing = "processing"
	WithdrawalStatusPending    = "pending"
	WithdrawalStatusPaid       = "paid"
	WithdrawalStatusFailed     = "failed"
	WithdrawalStatusCanceled   = "canceled"
)

type Sale struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	OwnerUserID uuid.UUID  `gorm:"type:uuid;index;not null" json:"owner_user_id"`
	RouterID    *uuid.UUID `gorm:"type:uuid;index" json:"router_id,omitempty"`
	PlanID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"plan_id"`
	VoucherID   uuid.UUID  `gorm:"type:uuid;uniqueIndex;not null" json:"voucher_id"`

	HotspotPurchaseID *uuid.UUID `gorm:"type:uuid;uniqueIndex" json:"hotspot_purchase_id,omitempty"`

	Source string `gorm:"size:32;index;not null" json:"source"`

	CustomerName string `gorm:"size:160;index" json:"customer_name"`
	Phone        string `gorm:"size:32;index" json:"phone"`

	GrossAmount       int64 `json:"gross_amount"`
	CommissionRateBPS int   `json:"commission_rate_bps"`
	PlatformFeeAmount int64 `json:"platform_fee_amount"`
	MerchantNetAmount int64 `json:"merchant_net_amount"`

	Currency string `gorm:"size:8;index;not null" json:"currency"`

	PaymentProvider  string `gorm:"size:64;index" json:"payment_provider"`
	PaymentReference string `gorm:"size:160;index" json:"payment_reference"`
	PaymentStatus    string `gorm:"size:32;index" json:"payment_status"`

	SoldAt          time.Time  `gorm:"index" json:"sold_at"`
	CreatedByUserID *uuid.UUID `gorm:"type:uuid;index" json:"created_by_user_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Sale) BeforeCreate(_ *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

type Wallet struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	OwnerUserID *uuid.UUID `gorm:"type:uuid;index" json:"owner_user_id,omitempty"`
	WalletType  string     `gorm:"size:32;index;not null" json:"wallet_type"`
	Currency    string     `gorm:"size:8;index;not null" json:"currency"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (w *Wallet) BeforeCreate(_ *gorm.DB) error {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	return nil
}

type WalletTransaction struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	WalletID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"wallet_id"`
	OwnerUserID *uuid.UUID `gorm:"type:uuid;index" json:"owner_user_id,omitempty"`

	Type      string `gorm:"size:48;index;not null" json:"type"`
	Direction string `gorm:"size:16;index;not null" json:"direction"`

	Amount   int64  `json:"amount"`
	Currency string `gorm:"size:8;index;not null" json:"currency"`

	ReferenceType  string     `gorm:"size:64;index" json:"reference_type"`
	ReferenceID    *uuid.UUID `gorm:"type:uuid;index" json:"reference_id,omitempty"`
	IdempotencyKey string     `gorm:"uniqueIndex;not null" json:"idempotency_key"`
	Description    string     `json:"description"`

	CreatedByUserID *uuid.UUID `gorm:"type:uuid;index" json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func (t *WalletTransaction) BeforeCreate(_ *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

type Withdrawal struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	WalletID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"wallet_id"`
	OwnerUserID *uuid.UUID `gorm:"type:uuid;index" json:"owner_user_id,omitempty"`
	WalletType  string     `gorm:"size:32;index;not null" json:"wallet_type"`

	Amount   int64  `json:"amount"`
	Currency string `gorm:"size:8;index;not null" json:"currency"`

	PayoutProvider    string `gorm:"size:64;index" json:"payout_provider"`
	PayoutDestination string `gorm:"size:64" json:"payout_destination"`
	PayoutAccountName string `gorm:"size:160;index" json:"payout_account_name"`
	PayeeNameStatus   string `gorm:"size:64;index" json:"payee_name_status"`

	Status                string `gorm:"size:32;index;not null" json:"status"`
	MerchantReference     string `gorm:"size:160;index" json:"merchant_reference"`
	ProviderReference     string `gorm:"size:160;index" json:"provider_reference"`
	ProviderStatus        string `gorm:"size:64;index" json:"provider_status"`
	ProviderStatusCode    string `gorm:"size:64" json:"provider_status_code"`
	ProviderStatusMessage string `gorm:"size:255" json:"provider_status_message"`
	Vendor                string `gorm:"size:80" json:"vendor"`
	VendorTransactionID   string `gorm:"size:160;index" json:"vendor_transaction_id"`
	FailureReason         string `json:"failure_reason"`

	RequestedByUserID uuid.UUID  `gorm:"type:uuid;index;not null" json:"requested_by_user_id"`
	ProcessedAt       *time.Time `json:"processed_at,omitempty"`
	PaidAt            *time.Time `json:"paid_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (w *Withdrawal) BeforeCreate(_ *gorm.DB) error {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	return nil
}

type FinanceActionLog struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	ActorUserID uuid.UUID  `gorm:"type:uuid;index;not null" json:"actor_user_id"`
	Action      string     `gorm:"size:80;index;not null" json:"action"`
	TargetType  string     `gorm:"size:80;index" json:"target_type"`
	TargetID    *uuid.UUID `gorm:"type:uuid;index" json:"target_id,omitempty"`
	Amount      int64      `json:"amount"`
	Currency    string     `gorm:"size:8" json:"currency"`
	Reason      string     `json:"reason"`

	CreatedAt time.Time `json:"created_at"`
}

func (a *FinanceActionLog) BeforeCreate(_ *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}
