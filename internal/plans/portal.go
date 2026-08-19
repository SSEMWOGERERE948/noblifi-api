package plans

import "github.com/google/uuid"

// ActiveListForUser returns only active packages owned by this HotSpot account.
//
// This is intentionally defined here only. Do not duplicate this method in
// repository.go.
func (r *Repository) ActiveListForUser(userID uuid.UUID) ([]Plan, error) {
	var items []Plan

	err := r.db.
		Where(
			"user_id = ? AND is_active = ?",
			userID,
			true,
		).
		Order(
			"price asc, duration_minutes asc, created_at desc",
		).
		Find(&items).
		Error

	return items, err
}

// ActiveListForUser is intentionally defined here only. Do not duplicate this
// method in service.go.
func (s *Service) ActiveListForUser(userID uuid.UUID) ([]Plan, error) {
	items, err := s.repo.ActiveListForUser(userID)
	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i] = hydratePlanDurationPresentation(items[i])
	}

	return items, nil
}