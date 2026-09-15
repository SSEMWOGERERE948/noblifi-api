package routers

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(router *Router) error {
	return r.db.Create(router).Error
}

func (r *Repository) List() ([]Router, error) {
	var routers []Router

	err := r.db.
		Where("deleted_at IS NULL").
		Order("created_at desc").
		Find(&routers).
		Error

	return routers, err
}

func (r *Repository) ListForUser(userID uuid.UUID) ([]Router, error) {
	var routers []Router

	err := r.db.
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Order("created_at desc").
		Find(&routers).
		Error

	return routers, err
}

func (r *Repository) Find(id uuid.UUID) (Router, error) {
	var router Router

	err := r.db.
		Preload("Interfaces").
		Preload("PortAssignments").
		Preload("SetupSession").
		Preload("NetworkProfile").
		Where("deleted_at IS NULL").
		First(&router, "id = ?", id).
		Error

	return router, err
}

func (r *Repository) FindForUser(id uuid.UUID, userID uuid.UUID) (Router, error) {
	var router Router

	err := r.db.
		Preload("Interfaces").
		Preload("PortAssignments").
		Preload("SetupSession").
		Preload("NetworkProfile").
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		First(&router, "id = ?", id).
		Error

	return router, err
}

func (r *Repository) FindByClaimToken(token string) (Router, error) {
	var router Router

	err := r.db.
		Preload("PortAssignments").
		Preload("SetupSession").
		Preload("NetworkProfile").
		Where("deleted_at IS NULL").
		First(&router, "claim_token = ?", token).
		Error

	return router, err
}

func (r *Repository) UpdateProvisioningStatus(token string, serial string, status string) (Router, error) {
	token = strings.TrimSpace(token)
	serial = strings.TrimSpace(serial)
	status = strings.TrimSpace(status)

	if token == "" {
		return Router{}, errors.New("claim token is required")
	}

	var router Router
	if err := r.db.
		Where("claim_token = ?", token).
		Where("deleted_at IS NULL").
		First(&router).
		Error; err != nil {
		return Router{}, err
	}

	now := time.Now().UTC()
	updates := map[string]any{
		"last_seen_at": now,
		"updated_at":   now,
	}

	if serial != "" {
		updates["serial_number"] = serial
	}

	if status != "" {
		switch strings.ToLower(status) {
		case "installed":
			updates["status"] = "provisioned"
			updates["provisioned_at"] = now
		case "failed":
			updates["status"] = "failed"
		default:
			updates["status"] = status
		}
	}

	if err := r.db.
		Model(&Router{}).
		Where("id = ?", router.ID).
		Updates(updates).
		Error; err != nil {
		return Router{}, err
	}

	if err := r.db.
		Where("id = ?", router.ID).
		First(&router).
		Error; err != nil {
		return Router{}, err
	}

	return router, nil
}

func (r *Repository) Save(router *Router) error {
	return r.db.Save(router).Error
}

func (r *Repository) ReplacePortAssignments(
	routerID uuid.UUID,
	assignments []RouterPortAssignment,
) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("router_id = ?", routerID).
			Delete(&RouterPortAssignment{}).
			Error; err != nil {
			return err
		}

		if len(assignments) == 0 {
			return nil
		}

		return tx.Create(&assignments).Error
	})
}

func (r *Repository) SetupSession(routerID uuid.UUID) (RouterSetupSession, error) {
	var session RouterSetupSession

	err := r.db.
		First(&session, "router_id = ?", routerID).
		Error

	return session, err
}

func (r *Repository) SaveSetupSession(session *RouterSetupSession) error {
	return r.db.Save(session).Error
}

func (r *Repository) EnsureSetupSession(routerID uuid.UUID) (RouterSetupSession, error) {
	session, err := r.SetupSession(routerID)
	if err == nil {
		return session, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return RouterSetupSession{}, err
	}

	session = RouterSetupSession{
		RouterID:         routerID,
		CurrentStep:      "remote_access",
		DeploymentStatus: "draft",
	}

	return session, r.db.Create(&session).Error
}

func (r *Repository) Interfaces(routerID uuid.UUID) ([]RouterInterface, error) {
	var interfaces []RouterInterface

	err := r.db.
		Order("name asc").
		Find(&interfaces, "router_id = ?", routerID).
		Error

	return interfaces, err
}

func (r *Repository) ReplaceInterfaces(
	routerID uuid.UUID,
	interfaces []RouterInterface,
) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("router_id = ?", routerID).
			Delete(&RouterInterface{}).
			Error; err != nil {
			return err
		}

		if len(interfaces) == 0 {
			return nil
		}

		return tx.Create(&interfaces).Error
	})
}

func (r *Repository) UpsertInterface(
	routerID uuid.UUID,
	iface RouterInterface,
) error {
	iface.RouterID = routerID

	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where(
				"router_id = ? AND name = ?",
				routerID,
				iface.Name,
			).
			Delete(&RouterInterface{}).
			Error; err != nil {
			return err
		}

		return tx.Create(&iface).Error
	})
}

func (r *Repository) CreateConfigLog(log *RouterConfigLog) error {
	return r.db.Create(log).Error
}

func (r *Repository) NetworkProfile(
	routerID uuid.UUID,
) (RouterNetworkProfile, error) {
	var profile RouterNetworkProfile

	err := r.db.
		First(&profile, "router_id = ?", routerID).
		Error

	return profile, err
}

func (r *Repository) SaveNetworkProfile(profile *RouterNetworkProfile) error {
	return r.db.Save(profile).Error
}

func (r *Repository) CreateNetworkProfile(profile *RouterNetworkProfile) error {
	return r.db.Create(profile).Error
}

// HotspotNameForRouter resolves the tenant-specific hotspot name through:
//
//	router.id -> router.user_id -> users.id -> users.hotspot_name
//
// This prevents a router from falling back to a shared/global HotSpot name
// when generating its captive-portal identity and RouterOS dns-name.
func (r *Repository) HotspotNameForRouter(routerID uuid.UUID) (string, error) {
	var result struct {
		HotspotName *string `gorm:"column:hotspot_name"`
	}

	tx := r.db.
		Table("routers AS r").
		Select("u.hotspot_name").
		Joins("LEFT JOIN users AS u ON u.id = r.user_id").
		Where("r.id = ?", routerID).
		Limit(1).
		Scan(&result)

	if tx.Error != nil {
		return "", tx.Error
	}

	if tx.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}

	if result.HotspotName == nil {
		return "", nil
	}

	return strings.TrimSpace(*result.HotspotName), nil
}

// HotspotNameForClaimToken resolves the exact user-selected hotspot_name for
// a router claim token. It is useful for provisioning paths that start from
// /provisioning/config/:token rather than a router UUID.
func (r *Repository) HotspotNameForClaimToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("claim token is required")
	}

	var result struct {
		HotspotName *string `gorm:"column:hotspot_name"`
	}

	tx := r.db.
		Table("routers AS r").
		Select("u.hotspot_name").
		Joins("LEFT JOIN users AS u ON u.id = r.user_id").
		Where("r.claim_token = ?", token).
		Limit(1).
		Scan(&result)

	if tx.Error != nil {
		return "", tx.Error
	}

	if tx.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}

	if result.HotspotName == nil {
		return "", nil
	}

	return strings.TrimSpace(*result.HotspotName), nil
}
