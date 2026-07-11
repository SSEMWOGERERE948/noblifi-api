package plans

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

func (r *Repository) Create(plan *Plan) error {
	return r.db.Create(plan).Error
}

func (r *Repository) List() ([]Plan, error) {
	var plans []Plan
	err := r.db.Order("created_at desc").Find(&plans).Error
	return plans, err
}

func (r *Repository) Find(id uuid.UUID) (Plan, error) {
	var plan Plan
	err := r.db.First(&plan, "id = ?", id).Error
	return plan, err
}

func (r *Repository) Save(plan *Plan) error {
	return r.db.Save(plan).Error
}
