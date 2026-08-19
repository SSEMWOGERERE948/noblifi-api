package plans

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(
	plan Plan,
	userID *uuid.UUID,
	isSuperadmin bool,
) (Plan, error) {
	if plan.ID == uuid.Nil {
		plan.ID = uuid.New()
	}

	if !isSuperadmin {
		if userID == nil || *userID == uuid.Nil {
			return Plan{}, errors.New(
				"authenticated user is required to create a plan",
			)
		}

		plan.UserID = userID
	}

	if err := normalizePlanForCreate(&plan); err != nil {
		return Plan{}, err
	}

	if err := s.repo.Create(&plan); err != nil {
		return Plan{}, err
	}

	return hydratePlanDurationPresentation(plan), nil
}

func (s *Service) List(
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Plan, error) {
	var items []Plan
	var err error

	if isSuperadmin || userID == nil {
		items, err = s.repo.List()
	} else {
		items, err = s.repo.ListForUser(*userID)
	}

	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i] = hydratePlanDurationPresentation(items[i])
	}

	return items, nil
}

func (s *Service) ActiveList() ([]Plan, error) {
	items, err := s.repo.ActiveList()
	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i] = hydratePlanDurationPresentation(items[i])
	}

	return items, nil
}

func (s *Service) Find(
	id uuid.UUID,
	userID *uuid.UUID,
	isSuperadmin bool,
) (Plan, error) {
	var plan Plan
	var err error

	if isSuperadmin || userID == nil {
		plan, err = s.repo.Find(id)
	} else {
		plan, err = s.repo.FindForUser(id, *userID)
	}

	if err != nil {
		return plan, err
	}

	return hydratePlanDurationPresentation(plan), nil
}

func (s *Service) Patch(
	id uuid.UUID,
	input PatchInput,
	userID *uuid.UUID,
	isSuperadmin bool,
) (Plan, error) {
	plan, err := s.Find(id, userID, isSuperadmin)
	if err != nil {
		return plan, err
	}

	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" {
			return plan, errors.New("plan name is required")
		}
		plan.Name = name
	}

	if input.Price != nil {
		if *input.Price < 0 {
			return plan, errors.New("price cannot be negative")
		}
		plan.Price = *input.Price
	}

	if input.MaxDevices != nil {
		if *input.MaxDevices < 1 {
			return plan, errors.New("max devices must be at least 1")
		}
		plan.MaxDevices = *input.MaxDevices
	}

	if input.UploadSpeed != nil {
		plan.UploadSpeed = strings.TrimSpace(*input.UploadSpeed)
	}

	if input.DownloadSpeed != nil {
		plan.DownloadSpeed = strings.TrimSpace(*input.DownloadSpeed)
	}

	if input.DataLimitMB != nil {
		if *input.DataLimitMB < 0 {
			return plan, errors.New("data limit cannot be negative")
		}

		if *input.DataLimitMB == 0 {
			plan.DataLimitMB = nil
		} else {
			value := *input.DataLimitMB
			plan.DataLimitMB = &value
		}
	}

	if input.IsActive != nil {
		plan.IsActive = *input.IsActive
	}

	if err := applyDurationPatch(&plan, input); err != nil {
		return plan, err
	}

	if err := validatePlan(plan); err != nil {
		return plan, err
	}

	if err := s.repo.Save(&plan); err != nil {
		return plan, err
	}

	return hydratePlanDurationPresentation(plan), nil
}

func normalizePlanForCreate(plan *Plan) error {
	if plan == nil {
		return errors.New("plan is required")
	}

	plan.Name = strings.TrimSpace(plan.Name)
	plan.UploadSpeed = strings.TrimSpace(plan.UploadSpeed)
	plan.DownloadSpeed = strings.TrimSpace(plan.DownloadSpeed)

	if plan.Name == "" {
		return errors.New("plan name is required")
	}

	if plan.Price < 0 {
		return errors.New("price cannot be negative")
	}

	if plan.MaxDevices <= 0 {
		plan.MaxDevices = 1
	}

	plan.IsActive = true

	if plan.DataLimitMB != nil {
		if *plan.DataLimitMB < 0 {
			return errors.New("data limit cannot be negative")
		}
		if *plan.DataLimitMB == 0 {
			plan.DataLimitMB = nil
		}
	}

	if err := normalizeCreateDuration(plan); err != nil {
		return err
	}

	return validatePlan(*plan)
}

func normalizeCreateDuration(plan *Plan) error {
	unit := strings.TrimSpace(plan.DurationUnit)

	if plan.DurationValue > 0 || unit != "" {
		normalizedUnit, err := normalizeDurationUnit(unit)
		if err != nil {
			return err
		}

		if plan.DurationValue <= 0 {
			return errors.New("duration value must be greater than zero")
		}

		minutes, err := durationToMinutes(plan.DurationValue, normalizedUnit)
		if err != nil {
			return err
		}

		plan.DurationUnit = normalizedUnit
		plan.DurationMinutes = minutes
		return nil
	}

	if plan.DurationMinutes <= 0 {
		return errors.New("duration is required")
	}

	plan.DurationValue, plan.DurationUnit =
		deriveDurationPresentation(plan.DurationMinutes)

	return nil
}

func applyDurationPatch(plan *Plan, input PatchInput) error {
	if plan == nil {
		return errors.New("plan is required")
	}

	hasValue := input.DurationValue != nil
	hasUnit := input.DurationUnit != nil
	hasLegacyMinutes := input.DurationMinutes != nil

	if !hasValue && !hasUnit && !hasLegacyMinutes {
		return nil
	}

	if hasValue || hasUnit {
		value := plan.DurationValue
		unit := plan.DurationUnit

		if value <= 0 || strings.TrimSpace(unit) == "" {
			value, unit = deriveDurationPresentation(plan.DurationMinutes)
		}

		if input.DurationValue != nil {
			value = *input.DurationValue
		}

		if input.DurationUnit != nil {
			unit = *input.DurationUnit
		}

		if value <= 0 {
			return errors.New("duration value must be greater than zero")
		}

		normalizedUnit, err := normalizeDurationUnit(unit)
		if err != nil {
			return err
		}

		minutes, err := durationToMinutes(value, normalizedUnit)
		if err != nil {
			return err
		}

		plan.DurationValue = value
		plan.DurationUnit = normalizedUnit
		plan.DurationMinutes = minutes
		return nil
	}

	if input.DurationMinutes != nil {
		if *input.DurationMinutes <= 0 {
			return errors.New("duration minutes must be greater than zero")
		}

		plan.DurationMinutes = *input.DurationMinutes
		plan.DurationValue, plan.DurationUnit =
			deriveDurationPresentation(plan.DurationMinutes)
	}

	return nil
}

func validatePlan(plan Plan) error {
	if strings.TrimSpace(plan.Name) == "" {
		return errors.New("plan name is required")
	}

	if plan.Price < 0 {
		return errors.New("price cannot be negative")
	}

	if plan.DurationMinutes <= 0 {
		return errors.New("duration must be greater than zero")
	}

	if plan.MaxDevices < 1 {
		return errors.New("max devices must be at least 1")
	}

	if plan.DataLimitMB != nil && *plan.DataLimitMB <= 0 {
		return errors.New(
			"data limit must be greater than zero or omitted for unlimited data",
		)
	}

	return nil
}

func normalizeDurationUnit(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "minute", "minutes", "min", "mins":
		return DurationUnitMinutes, nil
	case "hour", "hours", "hr", "hrs":
		return DurationUnitHours, nil
	case "week", "weeks", "wk", "wks":
		return DurationUnitWeeks, nil
	case "month", "months", "mo", "mos":
		return DurationUnitMonths, nil
	default:
		return "", errors.New(
			"duration unit must be minutes, hours, weeks, or months",
		)
	}
}

func durationToMinutes(value int, unit string) (int, error) {
	if value <= 0 {
		return 0, errors.New("duration value must be greater than zero")
	}

	var multiplier int

	switch unit {
	case DurationUnitMinutes:
		multiplier = 1
	case DurationUnitHours:
		multiplier = 60
	case DurationUnitWeeks:
		multiplier = 7 * 24 * 60
	case DurationUnitMonths:
		multiplier = 30 * 24 * 60
	default:
		return 0, errors.New("invalid duration unit")
	}

	maxInt := int(^uint(0) >> 1)
	if value > maxInt/multiplier {
		return 0, errors.New("duration is too large")
	}

	return value * multiplier, nil
}

func deriveDurationPresentation(minutes int) (int, string) {
	if minutes <= 0 {
		return 0, DurationUnitMinutes
	}

	monthMinutes := 30 * 24 * 60
	weekMinutes := 7 * 24 * 60

	if minutes >= monthMinutes && minutes%monthMinutes == 0 {
		return minutes / monthMinutes, DurationUnitMonths
	}

	if minutes >= weekMinutes && minutes%weekMinutes == 0 {
		return minutes / weekMinutes, DurationUnitWeeks
	}

	if minutes >= 60 && minutes%60 == 0 {
		return minutes / 60, DurationUnitHours
	}

	return minutes, DurationUnitMinutes
}

func hydratePlanDurationPresentation(plan Plan) Plan {
	unit, err := normalizeDurationUnit(plan.DurationUnit)
	if err == nil && plan.DurationValue > 0 {
		calculated, calcErr := durationToMinutes(plan.DurationValue, unit)
		if calcErr == nil && calculated == plan.DurationMinutes {
			plan.DurationUnit = unit
			return plan
		}
	}

	plan.DurationValue, plan.DurationUnit =
		deriveDurationPresentation(plan.DurationMinutes)

	return plan
}

func DurationLabel(plan Plan) string {
	plan = hydratePlanDurationPresentation(plan)

	unit := plan.DurationUnit
	if plan.DurationValue == 1 {
		unit = strings.TrimSuffix(unit, "s")
	}

	return fmt.Sprintf("%d %s", plan.DurationValue, unit)
}