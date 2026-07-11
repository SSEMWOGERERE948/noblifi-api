package vouchers

import "gorm.io/gorm"

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
