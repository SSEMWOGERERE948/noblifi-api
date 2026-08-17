package vouchers

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{
		db: db,
	}
}

// CreateMany inserts a batch of vouchers.
//
// If the slice is empty, there is nothing to insert.
func (r *Repository) CreateMany(
	vouchers []Voucher,
) error {
	if len(vouchers) == 0 {
		return nil
	}

	return r.db.
		Create(&vouchers).
		Error
}

// CodeExists checks whether a voucher code already exists.
//
// This is important because Voucher.Code has a unique index,
// and short voucher codes such as 4-digit numeric codes have
// a higher chance of collisions.
func (r *Repository) CodeExists(
	code string,
) (bool, error) {
	var count int64

	err := r.db.
		Model(&Voucher{}).
		Where("code = ?", code).
		Count(&count).
		Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// List returns all vouchers ordered from newest to oldest.
//
// This is used for superadmin/global voucher access.
func (r *Repository) List() (
	[]Voucher,
	error,
) {
	var vouchers []Voucher

	err := r.db.
		Order("created_at desc").
		Find(&vouchers).
		Error

	return vouchers, err
}

// ListForUser returns vouchers belonging to one user only.
func (r *Repository) ListForUser(
	userID uuid.UUID,
) ([]Voucher, error) {
	var vouchers []Voucher

	err := r.db.
		Where("user_id = ?", userID).
		Order("created_at desc").
		Find(&vouchers).
		Error

	return vouchers, err
}

// FindForUser returns a single voucher only when it belongs
// to the supplied user.
func (r *Repository) FindForUser(
	id uuid.UUID,
	userID uuid.UUID,
) (Voucher, error) {
	var voucher Voucher

	err := r.db.
		Where("user_id = ?", userID).
		First(
			&voucher,
			"id = ?",
			id,
		).
		Error

	return voucher, err
}