package vouchers

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateMany(vouchers []Voucher) error {
	return r.db.Create(&vouchers).Error
}

func (r *Repository) List() ([]Voucher, error) {
	var vouchers []Voucher
	err := r.db.Order("created_at desc").Find(&vouchers).Error
	return vouchers, err
}

func (r *Repository) ListForUser(userID uuid.UUID) ([]Voucher, error) {
	var vouchers []Voucher
	err := r.db.Where("user_id = ?", userID).Order("created_at desc").Find(&vouchers).Error
	return vouchers, err
}

func (r *Repository) FindForUser(id uuid.UUID, userID uuid.UUID) (Voucher, error) {
	var voucher Voucher
	err := r.db.Where("user_id = ?", userID).First(&voucher, "id = ?", id).Error
	return voucher, err
}
