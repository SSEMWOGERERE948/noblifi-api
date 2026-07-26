package vouchers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

type RadiusSyncer interface {
	SyncVoucherForVoucher(voucher Voucher) error
}

type Service struct {
	repo   *Repository
	radius RadiusSyncer
}

func NewService(repo *Repository, radius RadiusSyncer) *Service {
	if radius == nil {
		panic("voucher service requires RADIUS syncer")
	}

	return &Service{
		repo:   repo,
		radius: radius,
	}
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
		items = append(items, Voucher{
			PlanID: planID,
			Code:   code(),
			Status: "unused",
		})
	}

	if err := s.repo.CreateMany(items); err != nil {
		return nil, err
	}

	for _, item := range items {
		if err := s.radius.SyncVoucherForVoucher(item); err != nil {
			return items, fmt.Errorf(
				"voucher %s created but RADIUS sync failed: %w",
				item.Code,
				err,
			)
		}
	}

	return items, nil
}

func (s *Service) List() ([]Voucher, error) {
	return s.repo.List()
}

func code() string {
	bytes := make([]byte, 4)

	if _, err := rand.Read(bytes); err != nil {
		return "NF-" + uuid.NewString()[:8]
	}

	return "NF-" + hex.EncodeToString(bytes)
}