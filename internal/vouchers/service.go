package vouchers

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

const (
	ChannelMobileMoneyOnline = "mobile_money_online"
	ChannelPhysical          = "physical"
	MaxVoucherBatchSize      = 500
	DefaultOnlinePoolSize    = 500
)

var (
	templates = map[string]bool{
		"compact":      true,
		"receipt":      true,
		"scratch_card": true,
	}
	patterns = map[string]bool{
		"alphanumeric": true,
		"numeric":      true,
		"segmented":    true,
	}
)

type Service struct {
	repo   *Repository
	radius RadiusSyncer
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

type RadiusSyncer interface {
	SyncVoucherForVoucher(code string) error
}

func (s *Service) SetRadiusSyncer(syncer RadiusSyncer) {
	s.radius = syncer
}

type GenerateInput struct {
	PlanID   uuid.UUID
	Quantity int
	Channel  string
	Template string
	Pattern  string
}

func (s *Service) Generate(planID uuid.UUID, quantity int, userID *uuid.UUID, isSuperadmin bool) ([]Voucher, error) {
	return s.GeneratePhysical(GenerateInput{PlanID: planID, Quantity: quantity, Template: "compact", Pattern: "alphanumeric"}, userID, isSuperadmin)
}

func (s *Service) GenerateOnlineVouchers(planID uuid.UUID, userID *uuid.UUID, isSuperadmin bool) ([]Voucher, error) {
	return s.generate(GenerateInput{
		PlanID:   planID,
		Quantity: DefaultOnlinePoolSize,
		Channel:  ChannelMobileMoneyOnline,
		Pattern:  "alphanumeric",
	}, userID, isSuperadmin)
}

func (s *Service) GenerateOnlineVoucherCount(planID uuid.UUID, userID *uuid.UUID, isSuperadmin bool) (int, error) {
	items, err := s.GenerateOnlineVouchers(planID, userID, isSuperadmin)
	return len(items), err
}

func (s *Service) GeneratePhysical(input GenerateInput, userID *uuid.UUID, isSuperadmin bool) ([]Voucher, error) {
	if input.Template == "" {
		input.Template = "compact"
	}
	if !templates[input.Template] {
		return nil, fmt.Errorf("unknown physical voucher template: %s", input.Template)
	}
	if input.Pattern == "" {
		input.Pattern = "alphanumeric"
	}
	if !patterns[input.Pattern] {
		return nil, fmt.Errorf("unknown voucher code pattern: %s", input.Pattern)
	}
	input.Channel = ChannelPhysical
	return s.generate(input, userID, isSuperadmin)
}

func (s *Service) generate(input GenerateInput, userID *uuid.UUID, isSuperadmin bool) ([]Voucher, error) {
	quantity := input.Quantity
	if quantity < 1 {
		quantity = 1
	}
	if quantity > MaxVoucherBatchSize {
		quantity = MaxVoucherBatchSize
	}
	channel := input.Channel
	if channel == "" {
		channel = ChannelPhysical
	}
	pattern := input.Pattern
	if pattern == "" {
		pattern = "alphanumeric"
	}
	batchID := fmt.Sprintf("VCH-%s", strings.ToUpper(randomString("0123456789abcdef", 10)))
	items := make([]Voucher, 0, quantity)
	for i := 0; i < quantity; i++ {
		item := Voucher{
			PlanID:  input.PlanID,
			Code:    code(pattern),
			Channel: channel,
			BatchID: &batchID,
			Pattern: &pattern,
			Status:  "unused",
		}
		if !isSuperadmin && userID != nil {
			item.UserID = userID
		}
		if channel == ChannelPhysical {
			template := input.Template
			item.Template = &template
		}
		items = append(items, item)
	}
	err := s.repo.CreateMany(items)
	if err != nil {
		return items, err
	}
	if s.radius != nil {
		for _, item := range items {
			if err := s.radius.SyncVoucherForVoucher(item.Code); err != nil {
				return items, err
			}
		}
	}
	return items, err
}

func (s *Service) List(userID *uuid.UUID, isSuperadmin bool) ([]Voucher, error) {
	if isSuperadmin || userID == nil {
		return s.repo.List()
	}
	return s.repo.ListForUser(*userID)
}

func code(pattern string) string {
	switch pattern {
	case "numeric":
		return "NF-" + randomString("0123456789", 8)
	case "segmented":
		return "NF-" + randomString("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4) + "-" + randomString("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)
	default:
		return "NF-" + randomString("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 7)
	}
}

func randomString(alphabet string, length int) string {
	if alphabet == "" {
		alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	}
	var builder strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for builder.Len() < length {
		index, err := rand.Int(rand.Reader, max)
		if err != nil {
			return strings.ToUpper(uuid.NewString()[:length])
		}
		builder.WriteByte(alphabet[index.Int64()])
	}
	return builder.String()
}
