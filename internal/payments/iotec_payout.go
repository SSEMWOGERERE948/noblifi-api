package payments

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const (
	PayoutStatusProcessing = "processing"
	PayoutStatusPaid       = "paid"
	PayoutStatusFailed     = "failed"
)

type PayoutRequest struct {
	Reference string

	Phone string

	Name  string
	Email string

	Amount   int64
	Currency string
}

type PayoutResult struct {
	Provider string

	ProviderReference string
	MerchantReference string

	Status string

	RawStatus     string
	StatusCode    string
	StatusMessage string

	Vendor              string
	VendorTransactionID string

	Phone string

	// Mobile money payee name as verified/returned by ioTec, and the
	// verification state for that name (e.g. Fetched, Matched, Pending,
	// Failed, NotFound, NotMatched, Barred).
	PayeeName       string
	PayeeNameStatus string
}

type iotecDisbursementRequest struct {
	Category string `json:"category"`
	Currency string `json:"currency"`
	WalletID string `json:"walletId"`

	ExternalID string `json:"externalId,omitempty"`

	PayeeName  string `json:"payeeName,omitempty"`
	PayeeEmail string `json:"payeeEmail,omitempty"`

	Payee  string `json:"payee"`
	Amount int64  `json:"amount"`

	PayerNote string `json:"payerNote,omitempty"`
	PayeeNote string `json:"payeeNote,omitempty"`

	Channel string `json:"channel,omitempty"`
}

type iotecDisbursementResponse struct {
	ID string `json:"id"`

	Status        string `json:"status"`
	StatusCode    string `json:"statusCode"`
	StatusMessage string `json:"statusMessage"`

	ExternalID string `json:"externalId"`

	Vendor              string `json:"vendor"`
	VendorTransactionID string `json:"vendorTransactionId"`

	Payee string `json:"payee"`

	// PayeeName is the name ioTec fetched/verified against the mobile money
	// network for this payee. PayeeUploadName is the submitted name and is not
	// treated as verified identity. PayeeNameStatus describes how PayeeName was
	// determined/verified.
	PayeeName       string `json:"payeeName"`
	PayeeUploadName string `json:"payeeUploadName"`
	PayeeNameStatus string `json:"payeeNameStatus"`
}

func (s *Service) InitiatePayout(
	input PayoutRequest,
) (PayoutResult, error) {
	if err := s.configured(); err != nil {
		return PayoutResult{}, err
	}

	if input.Amount < 500 {
		return PayoutResult{},
			errors.New(
				"minimum ioTec withdrawal is UGX 500",
			)
	}

	phone, err := normalizeUgandaMSISDN(
		input.Phone,
	)
	if err != nil {
		return PayoutResult{}, err
	}

	reference := strings.TrimSpace(
		input.Reference,
	)

	if reference == "" {
		reference =
			"NOBLIFI-WD-" +
				strings.ToUpper(
					strings.ReplaceAll(
						uuid.NewString()[:8],
						"-",
						"",
					),
				)
	}

	currency := strings.ToUpper(
		strings.TrimSpace(
			input.Currency,
		),
	)

	if currency == "" {
		currency = s.currency()
	}

	token, err := s.iotecToken()
	if err != nil {
		return PayoutResult{},
			fmt.Errorf(
				"ioTec authentication failed: %w",
				err,
			)
	}

	body := iotecDisbursementRequest{
		Category: "MobileMoney",
		Currency: currency,
		WalletID: s.cfg.IotecWalletID,

		ExternalID: reference,

		PayeeName: strings.TrimSpace(input.Name),

		PayeeEmail: strings.TrimSpace(
			input.Email,
		),

		Payee: phone,

		Amount: input.Amount,

		PayerNote: "NobliFi merchant withdrawal",

		PayeeNote: "NobliFi withdrawal " +
			reference,

		Channel: "NobliFi",
	}

	var response iotecDisbursementResponse

	if err := s.iotecRequest(
		http.MethodPost,
		"/api/disbursements/disburse",
		token,
		body,
		&response,
	); err != nil {
		return PayoutResult{},
			fmt.Errorf(
				"initiate ioTec disbursement: %w",
				err,
			)
	}

	if strings.TrimSpace(response.ID) == "" {
		return PayoutResult{},
			errors.New(
				"ioTec disbursement did not return a transaction id",
			)
	}

	return payoutResultFromIotec(
		response,
		reference,
		phone,
	), nil
}

func (s *Service) CheckPayoutStatus(
	transactionID string,
) (PayoutResult, error) {
	transactionID = strings.TrimSpace(
		transactionID,
	)

	if transactionID == "" {
		return PayoutResult{},
			errors.New(
				"ioTec transaction id is required",
			)
	}

	token, err := s.iotecToken()
	if err != nil {
		return PayoutResult{},
			fmt.Errorf(
				"ioTec authentication failed: %w",
				err,
			)
	}

	path :=
		"/api/disbursements/status/" +
			url.PathEscape(transactionID)

	var response iotecDisbursementResponse

	if err := s.iotecRequest(
		http.MethodGet,
		path,
		token,
		nil,
		&response,
	); err != nil {
		return PayoutResult{},
			fmt.Errorf(
				"check ioTec disbursement: %w",
				err,
			)
	}

	if strings.TrimSpace(response.ID) == "" {
		response.ID = transactionID
	}

	return payoutResultFromIotec(
		response,
		response.ExternalID,
		response.Payee,
	), nil
}

// payoutResultFromIotec converts an ioTec disbursement response into a
// PayoutResult. This is the single place where every call site
// (InitiatePayout, CheckPayoutStatus) maps ioTec's
// response fields onto NobliFi's payout model, including the mobile money
// payee name and its verification status.
func payoutResultFromIotec(
	response iotecDisbursementResponse,
	fallbackReference string,
	fallbackPhone string,
) PayoutResult {
	reference := strings.TrimSpace(
		response.ExternalID,
	)

	if reference == "" {
		reference = strings.TrimSpace(
			fallbackReference,
		)
	}

	phone := strings.TrimSpace(
		response.Payee,
	)

	if phone == "" {
		phone = strings.TrimSpace(
			fallbackPhone,
		)
	}

	payeeName := strings.TrimSpace(
		response.PayeeName,
	)

	return PayoutResult{
		Provider: "iotec",

		ProviderReference: strings.TrimSpace(
			response.ID,
		),

		MerchantReference: reference,

		Status: normalizeIotecPayoutStatus(
			response.Status,
		),

		RawStatus: strings.TrimSpace(
			response.Status,
		),

		StatusCode: strings.TrimSpace(
			response.StatusCode,
		),

		StatusMessage: strings.TrimSpace(
			response.StatusMessage,
		),

		Vendor: strings.TrimSpace(
			response.Vendor,
		),

		VendorTransactionID: strings.TrimSpace(
			response.VendorTransactionID,
		),

		Phone: phone,

		PayeeName: payeeName,

		PayeeNameStatus: strings.TrimSpace(
			response.PayeeNameStatus,
		),
	}
}

func iotecPayeeNameVerified(status string) bool {
	switch normalizeProviderStatus(status) {
	case "fetched", "matched":
		return true
	default:
		return false
	}
}

func normalizeProviderStatus(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	status = strings.ReplaceAll(status, "_", "")
	status = strings.ReplaceAll(status, "-", "")
	status = strings.ReplaceAll(status, " ", "")
	return status
}

func normalizeIotecPayoutStatus(
	raw string,
) string {
	status := normalizeProviderStatus(raw)

	switch status {
	case "success":
		return PayoutStatusPaid

	case "failed",
		"cancelled",
		"canceled",
		"rejected",
		"rolledback":
		return PayoutStatusFailed

	case "pending",
		"senttovendor",
		"awaitingapproval",
		"scheduled":
		return PayoutStatusProcessing

	default:
		/*
			Unknown provider states must NEVER be
			treated as paid.
		*/
		return PayoutStatusProcessing
	}
}

func normalizeUgandaMSISDN(
	raw string,
) (string, error) {
	value := strings.TrimSpace(raw)

	replacer := strings.NewReplacer(
		" ", "",
		"-", "",
		"(", "",
		")", "",
	)

	value = replacer.Replace(value)

	value = strings.TrimPrefix(
		value,
		"+",
	)

	switch {
	case strings.HasPrefix(
		value,
		"256",
	):
		// already normalized

	case strings.HasPrefix(
		value,
		"0",
	):
		value =
			"256" +
				strings.TrimPrefix(
					value,
					"0",
				)

	case len(value) == 9:
		value = "256" + value
	}

	if len(value) != 12 ||
		!strings.HasPrefix(
			value,
			"256",
		) {
		return "",
			errors.New(
				"invalid Uganda mobile money phone number",
			)
	}

	for _, char := range value {
		if char < '0' || char > '9' {
			return "",
				errors.New(
					"invalid mobile money phone number",
				)
		}
	}

	return value, nil
}
