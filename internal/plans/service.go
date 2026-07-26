package plans

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type RadiusSyncer interface {
	SyncPlanForRadius(plan Plan) error
}

type Service struct {
	repo   *Repository
	radius RadiusSyncer
}

func NewService(repo *Repository, radius RadiusSyncer) *Service {
	if radius == nil {
		panic("plan service requires RADIUS syncer")
	}

	return &Service{
		repo:   repo,
		radius: radius,
	}
}

func (s *Service) Create(plan Plan) (Plan, error) {
	if err := validate(plan); err != nil {
		return plan, err
	}

	plan.IsActive = true

	if err := s.repo.Create(&plan); err != nil {
		return plan, err
	}

	if err := s.radius.SyncPlanForRadius(plan); err != nil {
		return plan, fmt.Errorf(
			"package created but RADIUS sync failed: %w",
			err,
		)
	}

	return plan, nil
}

func (s *Service) List() ([]Plan, error) {
	return s.repo.List()
}

func (s *Service) ActiveList() ([]Plan, error) {
	return s.repo.ActiveList()
}

func (s *Service) Find(id uuid.UUID) (Plan, error) {
	return s.repo.Find(id)
}

func (s *Service) Patch(id uuid.UUID, input Plan) (Plan, error) {
	plan, err := s.repo.Find(id)
	if err != nil {
		return plan, err
	}

	if strings.TrimSpace(input.Name) != "" {
		plan.Name = strings.TrimSpace(input.Name)
	}

	if input.Price > 0 {
		plan.Price = input.Price
	}

	if input.DurationMinutes > 0 {
		plan.DurationMinutes = input.DurationMinutes
	}

	if strings.TrimSpace(input.UploadSpeed) != "" {
		plan.UploadSpeed = strings.TrimSpace(input.UploadSpeed)
	}

	if strings.TrimSpace(input.DownloadSpeed) != "" {
		plan.DownloadSpeed = strings.TrimSpace(input.DownloadSpeed)
	}

	if input.MaxDevices > 0 {
		plan.MaxDevices = input.MaxDevices
	}

	if input.DataLimitMB != nil {
		plan.DataLimitMB = input.DataLimitMB
	}

	if err := validate(plan); err != nil {
		return plan, err
	}

	if err := s.repo.Save(&plan); err != nil {
		return plan, err
	}

	// Rebuild RADIUS package attributes whenever the package changes.
	if err := s.radius.SyncPlanForRadius(plan); err != nil {
		return plan, fmt.Errorf(
			"package saved but RADIUS sync failed: %w",
			err,
		)
	}

	return plan, nil
}

func validate(plan Plan) error {
	if strings.TrimSpace(plan.Name) == "" {
		return fmt.Errorf("package name is required")
	}

	if plan.Price < 0 {
		return fmt.Errorf("package price cannot be negative")
	}

	if plan.DurationMinutes <= 0 {
		return fmt.Errorf("duration_minutes must be greater than zero")
	}

	if strings.TrimSpace(plan.UploadSpeed) == "" {
		return fmt.Errorf("upload_speed is required")
	}

	if strings.TrimSpace(plan.DownloadSpeed) == "" {
		return fmt.Errorf("download_speed is required")
	}

	if plan.MaxDevices <= 0 {
		return fmt.Errorf("max_devices must be greater than zero")
	}

	return nil
}