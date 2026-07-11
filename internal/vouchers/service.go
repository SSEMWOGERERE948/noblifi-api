package vouchers

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
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

func (s *Service) Generate(planID uuid.UUID, quantity int) ([]Voucher, error) {
	if quantity < 1 {
		quantity = 1
	}
	if quantity > 500 {
		quantity = 500
	}
	items := make([]Voucher, 0, quantity)
	for i := 0; i < quantity; i++ {
		items = append(items, Voucher{PlanID: planID, Code: code(), Status: "unused"})
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

func (s *Service) List() ([]Voucher, error) {
	return s.repo.List()
}

func code() string {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString()[:8]
	}
	return "NF-" + hex.EncodeToString(bytes)
}
