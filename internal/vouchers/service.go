package vouchers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

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

// Generate creates `quantity` vouchers for the given plan and syncs each one
// to RADIUS.
//
// IMPORTANT: CreateMany commits all vouchers to the database before any
// RADIUS sync is attempted. That means every voucher already exists and is
// visible in the UI/API by the time we get to the sync loop below.
//
// Because of that, the sync loop must NOT abort on the first failure. Doing
// so previously left every voucher after the failing one silently without a
// radcheck row: the voucher existed and looked normal everywhere in NobliFi,
// but FreeRADIUS would reject it with "No Auth-Type found" because it was
// never inserted. We now attempt every voucher, log each failure as it
// happens, and report which codes failed at the end so the caller can retry
// or investigate instead of guessing.
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

	var failed []string

	for _, item := range items {
		if err := s.radius.SyncVoucherForVoucher(item); err != nil {
			log.Printf(
				"voucher %s created but RADIUS sync failed: %v",
				item.Code,
				err,
			)

			failed = append(failed, item.Code)

			continue
		}
	}

	if len(failed) > 0 {
		return items, fmt.Errorf(
			"%d of %d vouchers failed RADIUS sync and will not authenticate until re-synced: %s",
			len(failed),
			len(items),
			strings.Join(failed, ", "),
		)
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