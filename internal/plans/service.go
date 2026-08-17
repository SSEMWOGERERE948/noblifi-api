package plans

import "github.com/google/uuid"

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func preparePlanForCreate(plan *Plan) {
	if plan == nil {
		return
	}
	if plan.ID == uuid.Nil {
		plan.ID = uuid.New()
	}
	if !plan.IsActive {
		plan.IsActive = true
	}
}

func (s *Service) Create(plan Plan, userID *uuid.UUID, isSuperadmin bool) (Plan, error) {
	preparePlanForCreate(&plan)
	plan.IsActive = true
	if !isSuperadmin && userID != nil {
		plan.UserID = userID
	}
	err := s.repo.Create(&plan)
	return plan, err
}

func (s *Service) List(userID *uuid.UUID, isSuperadmin bool) ([]Plan, error) {
	if isSuperadmin || userID == nil {
		return s.repo.List()
	}
	return s.repo.ListForUser(*userID)
}

func (s *Service) ActiveList() ([]Plan, error) {
	return s.repo.ActiveList()
}

func (s *Service) Find(id uuid.UUID, userID *uuid.UUID, isSuperadmin bool) (Plan, error) {
	if isSuperadmin || userID == nil {
		return s.repo.Find(id)
	}
	return s.repo.FindForUser(id, *userID)
}

func (s *Service) Patch(id uuid.UUID, input Plan, userID *uuid.UUID, isSuperadmin bool) (Plan, error) {
	plan, err := s.Find(id, userID, isSuperadmin)
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
