package wireguard

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/radius"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrUnauthorized = errors.New("agent unauthorized")

type Service struct {
	db  *gorm.DB
	cfg config.Config
}

func NewService(db *gorm.DB, cfg config.Config) *Service {
	return &Service{db: db, cfg: cfg}
}

func (s *Service) AuthenticateAgent(token string) bool {
	expected := strings.TrimSpace(s.cfg.AgentToken)
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if expected == "" || token == "" {
		return false
	}
	if len(expected) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func (s *Service) QueuePeerUpsert(router routers.Router) (WireGuardJob, error) {
	if router.ID == uuid.Nil {
		return WireGuardJob{}, errors.New("router ID is required")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return WireGuardJob{}, errors.New("router WireGuard client IP is required")
	}
	if router.WireGuardPublicKey == nil || strings.TrimSpace(*router.WireGuardPublicKey) == "" {
		return WireGuardJob{}, errors.New("router WireGuard public key is required")
	}
	return s.QueueJob(
		router.ID,
		OperationUpsertPeer,
		strings.TrimSpace(*router.WireGuardPublicKey),
		strings.TrimSpace(*router.WireGuardTunnelIP)+"/32",
	)
}

// QueueRouterConfigure queues the second provisioning stage. The job intentionally
// carries no RADIUS secret, RouterOS password, or complete script. The agent fetches
// the desired configuration from an authenticated internal endpoint after claiming it.
func (s *Service) QueueRouterConfigure(router routers.Router, _ string) (WireGuardJob, error) {
	if router.ID == uuid.Nil {
		return WireGuardJob{}, errors.New("router ID is required")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return WireGuardJob{}, errors.New("router WireGuard client IP is required")
	}
	return s.QueueJob(router.ID, OperationConfigureRouter, "", "")
}

func (s *Service) QueuePeerRemoval(router routers.Router) (WireGuardJob, error) {
	if router.ID == uuid.Nil {
		return WireGuardJob{}, errors.New("router ID is required")
	}
	allowedIP := ""
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		allowedIP = strings.TrimSpace(*router.WireGuardTunnelIP) + "/32"
	}
	publicKey := ""
	if router.WireGuardPublicKey != nil {
		publicKey = strings.TrimSpace(*router.WireGuardPublicKey)
	}
	return s.QueueJob(router.ID, OperationRemovePeer, publicKey, allowedIP)
}

func (s *Service) QueueJob(routerID uuid.UUID, operation, publicKey, allowedIP string) (WireGuardJob, error) {
	now := time.Now().UTC()
	var job WireGuardJob
	err := s.db.Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where(
				"router_id = ? AND operation = ? AND status IN ?",
				routerID,
				operation,
				[]string{StatusQueued, StatusClaimed, StatusApplying, StatusRetrying},
			).
			Order("created_at desc").
			First(&job).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			job = WireGuardJob{
				RouterID:    routerID,
				Operation:   operation,
				Status:      StatusQueued,
				PublicKey:   strings.TrimSpace(publicKey),
				AllowedIP:   strings.TrimSpace(allowedIP),
				MaxAttempts: 5,
				AvailableAt: now,
			}
			return tx.Create(&job).Error
		}
		if err != nil {
			return err
		}
		job.PublicKey = strings.TrimSpace(publicKey)
		job.AllowedIP = strings.TrimSpace(allowedIP)
		job.Status = StatusQueued
		job.LastError = ""
		job.LockedBy = ""
		job.LockedAt = nil
		job.CompletedAt = nil
		job.AvailableAt = now
		return tx.Save(&job).Error
	})
	return job, err
}

func (s *Service) ClaimJob(agentID string, lease time.Duration) (WireGuardJob, bool, error) {
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	now := time.Now().UTC()
	expiredBefore := now.Add(-lease)
	var job WireGuardJob
	err := s.db.Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"(status IN ? AND available_at <= ?) OR (status IN ? AND locked_at < ?)",
				[]string{StatusQueued, StatusRetrying}, now,
				[]string{StatusClaimed, StatusApplying}, expiredBefore,
			).
			Order("available_at asc, created_at asc").
			First(&job).Error
		if err != nil {
			return err
		}
		job.Status = StatusClaimed
		job.LockedBy = strings.TrimSpace(agentID)
		job.LockedAt = &now
		job.AttemptCount++
		return tx.Save(&job).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return WireGuardJob{}, false, nil
	}
	return job, err == nil, err
}

func (s *Service) MarkApplying(jobID uuid.UUID, agentID string) error {
	return s.updateClaimedJob(jobID, agentID, func(job *WireGuardJob) {
		job.Status = StatusApplying
	})
}

func (s *Service) CompleteJob(jobID uuid.UUID, agentID string) error {
	now := time.Now().UTC()
	var completed WireGuardJob
	if err := s.updateClaimedJob(jobID, agentID, func(job *WireGuardJob) {
		job.Status = StatusSucceeded
		job.CompletedAt = &now
		job.LastError = ""
		completed = *job
	}); err != nil {
		return err
	}

	if err := s.applyRouterJobStatus(completed, ""); err != nil {
		return err
	}

	// Full router configuration requires both halves of the tunnel lifecycle:
	// the VPS peer must be installed and the MikroTik must report a current
	// handshake. If the handshake arrived first, this completion can queue the
	// second stage; otherwise WireGuardStatus will queue it later.
	if completed.Operation == OperationUpsertPeer {
		var router routers.Router
		if err := s.db.Preload("PortAssignments").First(&router, "id = ?", completed.RouterID).Error; err != nil {
			return fmt.Errorf("load router after peer completion: %w", err)
		}
		if router.WireGuardLastHandshakeAt == nil {
			return nil
		}
		if _, err := s.QueueRouterConfigure(router, ""); err != nil {
			return fmt.Errorf("queue configure_router job: %w", err)
		}
	}
	return nil
}

func (s *Service) FailJob(jobID uuid.UUID, agentID, message string) error {
	now := time.Now().UTC()
	var failed WireGuardJob
	safeMessage := safeError(message)
	if err := s.updateClaimedJob(jobID, agentID, func(job *WireGuardJob) {
		job.LastError = safeMessage
		if job.AttemptCount >= job.MaxAttempts {
			job.Status = StatusFailed
			job.CompletedAt = &now
			failed = *job
			return
		}
		job.Status = StatusRetrying
		delay := time.Duration(1<<min(job.AttemptCount, 6)) * time.Second
		job.AvailableAt = now.Add(delay)
		job.LockedBy = ""
		job.LockedAt = nil
		failed = *job
	}); err != nil {
		return err
	}
	if failed.Status == StatusFailed {
		return s.applyRouterJobStatus(failed, safeMessage)
	}
	return nil
}

func (s *Service) updateClaimedJob(jobID uuid.UUID, agentID string, apply func(*WireGuardJob)) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var job WireGuardJob
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&job, "id = ?", jobID).Error; err != nil {
			return err
		}
		if job.LockedBy != strings.TrimSpace(agentID) {
			return fmt.Errorf("job is not leased to this agent")
		}
		apply(&job)
		return tx.Save(&job).Error
	})
}

func (s *Service) ActiveServerPublicKey() (string, error) {
	var hb AgentHeartbeat
	err := s.db.
		Where("healthy = ? AND wire_guard_public_key <> ''", true).
		Order("last_seen_at desc").
		First(&hb).Error
	if err == nil {
		publicKey := strings.TrimSpace(hb.WireGuardPublicKey)
		if err := routers.ValidateWireGuardPublicKey(publicKey); err != nil {
			return "", fmt.Errorf("active WireGuard agent public key is invalid: %w", err)
		}
		return publicKey, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}
	if strings.TrimSpace(s.cfg.WireGuardPublicKey) != "" {
		publicKey := strings.TrimSpace(s.cfg.WireGuardPublicKey)
		if err := routers.ValidateWireGuardPublicKey(publicKey); err != nil {
			return "", fmt.Errorf("configured WireGuard public key is invalid: %w", err)
		}
		return publicKey, nil
	}
	return "", errors.New("no healthy WireGuard agent public key is available")
}

func (s *Service) Heartbeat(agentID, version, iface, publicKey string, peerCount int, healthy bool, lastReconciliation *time.Time) error {
	now := time.Now().UTC()
	var hb AgentHeartbeat
	err := s.db.First(&hb, "agent_id = ?", agentID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		hb = AgentHeartbeat{AgentID: agentID, CreatedAt: now}
	} else if err != nil {
		return err
	}
	hb.Version = version
	hb.WireGuardInterface = iface
	hb.WireGuardPublicKey = strings.TrimSpace(publicKey)
	hb.PeerCount = peerCount
	hb.Healthy = healthy
	hb.LastReconciliation = lastReconciliation
	hb.LastSeenAt = now
	return s.db.Save(&hb).Error
}

func (s *Service) applyRouterJobStatus(job WireGuardJob, message string) error {
	now := time.Now().UTC()
	updates := map[string]any{"updated_at": now}
	switch job.Operation {
	case OperationUpsertPeer, OperationReconcilePeer:
		if job.Status == StatusSucceeded {
			updates["wire_guard_peer_status"] = "peer_ready"
			updates["wire_guard_peer_updated_at"] = now
			updates["wire_guard_last_error"] = nil
			updates["provisioning_status"] = "wireguard_peer_ready"
			updates["provisioning_error"] = nil
			updates["wire_guard_status"] = gorm.Expr(
				"CASE WHEN wire_guard_last_handshake_at IS NULL THEN ? ELSE wire_guard_status END",
				"peer_ready",
			)
		} else if job.Status == StatusFailed {
			updates["wire_guard_status"] = "failed"
			updates["wire_guard_peer_status"] = "failed"
			updates["wire_guard_last_error"] = message
			updates["provisioning_status"] = "peer_failed"
			updates["provisioning_error"] = message
		}
	case OperationConfigureRouter:
		if job.Status == StatusSucceeded {
			updates["status"] = "online"
			updates["provisioning_status"] = "installed"
			updates["provisioning_error"] = nil
			updates["wire_guard_last_error"] = nil
			updates["last_seen_at"] = now
		} else if job.Status == StatusFailed {
			updates["provisioning_status"] = "router_config_failed"
			updates["provisioning_error"] = message
		}
	case OperationRemovePeer:
		if job.Status == StatusSucceeded {
			if job.AllowedIP != "" {
				nasName := strings.TrimSuffix(job.AllowedIP, "/32")
				if err := s.db.Where("nasname = ?", nasName).Delete(&radius.NAS{}).Error; err != nil {
					return err
				}
			}
			updates["wire_guard_status"] = "removed"
			updates["wire_guard_peer_status"] = "removed"
			updates["wire_guard_tunnel_ip"] = nil
			updates["wire_guard_public_key"] = nil
			updates["management_ip"] = nil
			updates["deleted_at"] = now
			updates["status"] = "deleted"
			updates["provisioning_status"] = "deleted"
		} else if job.Status == StatusFailed {
			updates["wire_guard_peer_status"] = "failed"
			updates["wire_guard_last_error"] = message
			updates["provisioning_error"] = message
		}
	}
	if len(updates) == 1 {
		return nil
	}
	return s.db.Model(&routers.Router{}).Where("id = ?", job.RouterID).Updates(updates).Error
}

func safeError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1000 {
		return value[:1000]
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
