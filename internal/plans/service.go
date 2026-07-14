package plans

import "github.com/google/uuid"

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(plan Plan) (Plan, error) {
	plan.IsActive = true
	err := s.repo.Create(&plan)
	return plan, err
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
	if input.Name != "" {
		plan.Name = input.Name
	}
	if input.Price != 0 {
		plan.Price = input.Price
	}
	if input.DurationMinutes != 0 {
		plan.DurationMinutes = input.DurationMinutes
	}
	if input.UploadSpeed != "" {
		plan.UploadSpeed = input.UploadSpeed
	}
	if input.DownloadSpeed != "" {
		plan.DownloadSpeed = input.DownloadSpeed
	}
	if input.MaxDevices != 0 {
		plan.MaxDevices = input.MaxDevices
	}
	err = s.repo.Save(&plan)
	return plan, err
}
