package wireguard

import (
	"time"

	"github.com/google/uuid"
)

const (
	OperationUpsertPeer      = "upsert_peer"
	OperationRemovePeer      = "remove_peer"
	OperationReconcilePeer   = "reconcile_peer"
	OperationConfigureRouter = "configure_router"
	OperationUpsertRadiusNAS = "upsert_radius_nas"
	OperationRemoveRadiusNAS = "remove_radius_nas"

	StatusQueued    = "queued"
	StatusClaimed   = "claimed"
	StatusApplying  = "applying"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusRetrying  = "retrying"
	StatusCancelled = "cancelled"
)

type WireGuardJob struct {
	ID           uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"router_id"`
	Operation    string     `gorm:"index;not null" json:"operation"`
	Status       string     `gorm:"index;not null;default:queued" json:"status"`
	PublicKey    string     `json:"public_key"`
	AllowedIP    string     `gorm:"index" json:"allowed_ip"`
	AttemptCount int        `gorm:"not null;default:0" json:"attempt_count"`
	MaxAttempts  int        `gorm:"not null;default:5" json:"max_attempts"`
	LastError    string     `json:"last_error"`
	LockedBy     string     `gorm:"index" json:"locked_by"`
	LockedAt     *time.Time `json:"locked_at"`
	AvailableAt  time.Time  `gorm:"index;not null" json:"available_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type AgentHeartbeat struct {
	ID                 uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	AgentID            string     `gorm:"uniqueIndex;not null" json:"agent_id"`
	Version            string     `json:"version"`
	WireGuardInterface string     `json:"wireguard_interface"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	PeerCount          int        `json:"peer_count"`
	Healthy            bool       `json:"healthy"`
	LastReconciliation *time.Time `json:"last_reconciliation"`
	LastSeenAt         time.Time  `gorm:"index;not null" json:"last_seen_at"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}
