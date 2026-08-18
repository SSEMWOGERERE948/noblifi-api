package wireguard

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
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

type RemoteAccessConfig struct {
	RouterID   uuid.UUID `json:"router_id"`
	RouterIP   string    `json:"router_ip"`
	WebPort    int       `json:"web_port"`
	WinboxPort int       `json:"winbox_port"`
}

type RemoteAccessTarget struct {
	RouterID   uuid.UUID `json:"router_id"`
	Name       string    `json:"name"`
	RouterIP   string    `json:"router_ip"`
	WebPort    int       `json:"web_port"`
	WinboxPort int       `json:"winbox_port"`
}

type TelemetryTarget struct {
	RouterID    uuid.UUID `json:"router_id"`
	Name        string    `json:"name"`
	RouterIP    string    `json:"router_ip"`
	APIPort     int       `json:"api_port"`
	APIUsername string    `json:"api_username"`
	APIPassword string    `json:"api_password"`
}

type DesiredRouterConfig struct {
	RouterID       string `json:"router_id"`
	ManagementIP   string `json:"management_ip"`
	ConfigRevision string `json:"config_revision"`
	APIUsername    string `json:"api_username"`
	APIPassword    string `json:"api_password"`
	APIPort        int    `json:"api_port"`
	APITLS         bool   `json:"api_tls"`
	RouterOSScript string `json:"routeros_script"`
}

type AgentTelemetryReport struct {
	Identity           string                    `json:"identity"`
	Model              string                    `json:"model"`
	RouterOSVersion    string                    `json:"routeros_version"`
	Uptime             string                    `json:"uptime"`
	CPULoad            string                    `json:"cpu_load"`
	FreeMemory         string                    `json:"free_memory"`
	TotalMemory        string                    `json:"total_memory"`
	ActiveHotspotUsers *int                      `json:"active_hotspot_users"`
	Interfaces         []routers.RouterInterface `json:"interfaces"`
	Error              string                    `json:"error"`
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
		hostOnly(strings.TrimSpace(*router.WireGuardTunnelIP))+"/32",
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
	existing, ok, err := s.existingConfigureJob(router.ID)
	if err != nil {
		return WireGuardJob{}, err
	}
	if ok {
		return existing, nil
	}
	return s.QueueJob(router.ID, OperationConfigureRouter, "", "")
}

func (s *Service) QueueRemoteAccess(router routers.Router) (WireGuardJob, error) {
	if router.ID == uuid.Nil {
		return WireGuardJob{}, errors.New("router ID is required")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return WireGuardJob{}, errors.New("router WireGuard client IP is required")
	}
	return s.QueueJob(router.ID, OperationUpsertRemoteAccess, "", "")
}

func (s *Service) DesiredRemoteAccess(routerID uuid.UUID) (RemoteAccessConfig, error) {
	var router routers.Router
	if err := s.db.First(&router, "id = ?", routerID).Error; err != nil {
		return RemoteAccessConfig{}, err
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return RemoteAccessConfig{}, errors.New("router WireGuard tunnel IP is missing")
	}
	if router.RemoteWebPort == nil && router.RemoteWinboxPort == nil {
		return RemoteAccessConfig{}, errors.New("router remote access ports are not assigned")
	}
	cfg := RemoteAccessConfig{
		RouterID: router.ID,
		RouterIP: strings.TrimSpace(*router.WireGuardTunnelIP),
	}
	if router.RemoteWebPort != nil {
		cfg.WebPort = *router.RemoteWebPort
	}
	if router.RemoteWinboxPort != nil {
		cfg.WinboxPort = *router.RemoteWinboxPort
	}
	return cfg, nil
}

func (s *Service) RemoteAccessTargets() ([]RemoteAccessTarget, error) {
	var records []routers.Router
	if err := s.db.
		Where("deleted_at IS NULL").
		Where("wire_guard_tunnel_ip IS NOT NULL AND wire_guard_tunnel_ip <> ''").
		Where("remote_access_status IN ?", []string{"queued", "ready", "failed"}).
		Where("remote_winbox_port IS NOT NULL").
		Order("created_at desc").
		Find(&records).Error; err != nil {
		return nil, err
	}

	targets := make([]RemoteAccessTarget, 0, len(records))
	for _, router := range records {
		routerIP := hostOnly(ptrValue(router.WireGuardTunnelIP))
		if routerIP == "" {
			continue
		}
		target := RemoteAccessTarget{
			RouterID: router.ID,
			Name:     router.Name,
			RouterIP: routerIP,
		}
		if router.RemoteWinboxPort != nil {
			target.WinboxPort = *router.RemoteWinboxPort
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func (s *Service) RecordRemoteAccessReady(routerID uuid.UUID) error {
	now := time.Now().UTC()
	return s.db.Model(&routers.Router{}).
		Where("id = ?", routerID).
		Updates(map[string]any{
			"remote_access_status":  "ready",
			"wire_guard_last_error": nil,
			"updated_at":            now,
		}).Error
}

func (s *Service) RecordRemoteAccessError(routerID uuid.UUID, message string) error {
	now := time.Now().UTC()
	msg := safeError(message)
	if msg == "" {
		msg = "remote access forwarder failed"
	}
	return s.db.Model(&routers.Router{}).
		Where("id = ?", routerID).
		Updates(map[string]any{
			"remote_access_status":  "failed",
			"wire_guard_last_error": msg,
			"updated_at":            now,
		}).Error
}

func (s *Service) TelemetryTargets() ([]TelemetryTarget, error) {
	var records []routers.Router
	if err := s.db.
		Where("deleted_at IS NULL").
		Where("wire_guard_tunnel_ip IS NOT NULL AND wire_guard_tunnel_ip <> ''").
		Order("created_at desc").
		Find(&records).Error; err != nil {
		return nil, err
	}

	targets := make([]TelemetryTarget, 0, len(records))
	for _, router := range records {
		routerIP := strings.TrimSpace(ptrValue(router.WireGuardTunnelIP))
		username := firstNonEmpty(ptrValue(router.APIUsername), s.cfg.RouterAPIUsername)
		password := s.routerAPIPassword(router)
		if routerIP == "" || username == "" || password == "" {
			continue
		}
		targets = append(targets, TelemetryTarget{
			RouterID:    router.ID,
			Name:        router.Name,
			RouterIP:    hostOnly(routerIP),
			APIPort:     8728,
			APIUsername: username,
			APIPassword: password,
		})
	}
	return targets, nil
}

func (s *Service) RecordAgentTelemetry(routerID uuid.UUID, input AgentTelemetryReport) error {
	var router routers.Router
	if err := s.db.First(&router, "id = ?", routerID).Error; err != nil {
		return err
	}

	now := time.Now().UTC()
	if strings.TrimSpace(input.Error) != "" {
		msg := safeError(input.Error)
		return s.db.Model(&routers.Router{}).
			Where("id = ?", routerID).
			Updates(map[string]any{
				"telemetry_last_error": msg,
				"updated_at":           now,
			}).Error
	}

	updates := map[string]any{
		"telemetry_updated_at": now,
		"telemetry_last_error": nil,
		"last_seen_at":         now,
		"status":               "online",
		"updated_at":           now,
	}
	if value := strings.TrimSpace(input.Model); value != "" {
		updates["model"] = value
	}
	if value := strings.TrimSpace(input.RouterOSVersion); value != "" {
		updates["router_os_version"] = value
	}
	if value := strings.TrimSpace(input.Uptime); value != "" {
		updates["uptime"] = value
	}
	if value := strings.TrimSpace(input.CPULoad); value != "" {
		updates["cpu_load"] = value
	}
	if value := strings.TrimSpace(input.FreeMemory); value != "" {
		updates["free_memory"] = value
	}
	if value := strings.TrimSpace(input.TotalMemory); value != "" {
		updates["total_memory"] = value
	}
	if input.ActiveHotspotUsers != nil {
		updates["active_hotspot_users"] = *input.ActiveHotspotUsers
	}

	if err := s.db.Model(&routers.Router{}).Where("id = ?", routerID).Updates(updates).Error; err != nil {
		return err
	}

	if len(input.Interfaces) > 0 {
		interfaces := make([]routers.RouterInterface, 0, len(input.Interfaces))
		for _, iface := range input.Interfaces {
			name := strings.TrimSpace(iface.Name)
			if name == "" {
				continue
			}
			iface.ID = uuid.Nil
			iface.RouterID = routerID
			iface.Name = name
			if iface.DiscoveredAt.IsZero() {
				iface.DiscoveredAt = now
			}
			interfaces = append(interfaces, iface)
		}
		if len(interfaces) > 0 {
			return s.db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Where("router_id = ?", routerID).Delete(&routers.RouterInterface{}).Error; err != nil {
					return err
				}
				return tx.Create(&interfaces).Error
			})
		}
	}
	return nil
}

func (s *Service) DesiredRouterConfig(routerID uuid.UUID) (DesiredRouterConfig, error) {
	var router routers.Router
	if err := s.db.Preload("PortAssignments").Preload("NetworkProfile").First(&router, "id = ?", routerID).Error; err != nil {
		return DesiredRouterConfig{}, err
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return DesiredRouterConfig{}, errors.New("router management tunnel IP is missing")
	}

	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{
			InterfaceName: assignment.InterfaceName,
			Role:          assignment.Role,
		})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}

	options := renderOptionsForRouter(router, s.cfg)
	options.RadiusServer = s.cfg.WireGuardServerIP
	options.LoginPageURL = normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL) + "/hotspot-login/" + router.ClaimToken

	script, err := portprofiles.RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		return DesiredRouterConfig{}, err
	}
	sum := sha256.Sum256([]byte(script))

	return DesiredRouterConfig{
		RouterID:       router.ID.String(),
		ManagementIP:   hostOnly(strings.TrimSpace(*router.WireGuardTunnelIP)),
		ConfigRevision: fmt.Sprintf("%x", sum[:]),
		APIUsername:    options.APIUsername,
		APIPassword:    options.APIPassword,
		APIPort:        8728,
		APITLS:         false,
		RouterOSScript: script,
	}, nil
}

func renderOptionsForRouter(router routers.Router, cfg config.Config) portprofiles.RenderOptions {
	if router.NetworkProfile != nil {
		profile := *router.NetworkProfile
		routers.NormalizeNetworkProfile(&profile, cfg)
		options := profile.RenderOptions()
		options.WalledGardenHosts = cfg.HotspotWalledGardenHosts
		return options
	}
	return portprofiles.RenderOptions{
		RadiusServer:        cfg.RadiusServer,
		RadiusSecret:        cfg.RadiusSecret,
		RouterIdentity:      cfg.RouterIdentityPrefix + "-Router",
		APIUsername:         cfg.RouterAPIUsername,
		APIPassword:         cfg.RouterAPIPassword,
		HotspotBridge:       cfg.HotspotBridgeName,
		StaffBridge:         cfg.StaffBridgeName,
		POSBridge:           cfg.POSBridgeName,
		CCTVBridge:          cfg.CCTVBridgeName,
		HotspotSubnet:       cfg.HotspotSubnetCIDR,
		HotspotGateway:      cfg.HotspotGatewayCIDR,
		HotspotPool:         cfg.HotspotPoolRange,
		StaffSubnet:         cfg.StaffSubnetCIDR,
		StaffGateway:        cfg.StaffGatewayCIDR,
		StaffPool:           cfg.StaffPoolRange,
		POSSubnet:           cfg.POSSubnetCIDR,
		POSGateway:          cfg.POSGatewayCIDR,
		POSPool:             cfg.POSPoolRange,
		CCTVSubnet:          cfg.CCTVSubnetCIDR,
		CCTVGateway:         cfg.CCTVGatewayCIDR,
		CCTVPool:            cfg.CCTVPoolRange,
		HotspotDNSName:      cfg.HotspotDNSName,
		HotspotPortalName:   cfg.HotspotPortalName,
		WalledGardenHosts:   cfg.HotspotWalledGardenHosts,
		DisableWWWService:   cfg.DisableWWWService,
		EnableAPIService:    cfg.EnableAPIService,
		EnableAPISSLService: cfg.EnableAPISSLService,
	}
}

func (s *Service) existingConfigureJob(routerID uuid.UUID) (WireGuardJob, bool, error) {
	var job WireGuardJob
	err := s.db.
		Where(
			"router_id = ? AND operation = ? AND status IN ?",
			routerID,
			OperationConfigureRouter,
			[]string{StatusQueued, StatusClaimed, StatusApplying, StatusRetrying},
		).
		Order("created_at desc").
		First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return WireGuardJob{}, false, nil
	}
	return job, err == nil, err
}

func (s *Service) QueuePeerRemoval(router routers.Router) (WireGuardJob, error) {
	if router.ID == uuid.Nil {
		return WireGuardJob{}, errors.New("router ID is required")
	}
	allowedIP := ""
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		allowedIP = hostOnly(strings.TrimSpace(*router.WireGuardTunnelIP)) + "/32"
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
		if router.RemoteWebPort != nil || router.RemoteWinboxPort != nil {
			if _, err := s.QueueRemoteAccess(router); err != nil {
				return fmt.Errorf("queue remote access job: %w", err)
			}
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
			updates["wire_guard_status"] = "configured"
			updates["wire_guard_peer_status"] = "configured"
			updates["last_seen_at"] = now
		} else if job.Status == StatusFailed {
			updates["provisioning_status"] = "router_config_failed"
			updates["provisioning_error"] = message
		}
	case OperationUpsertRemoteAccess:
		if job.Status == StatusSucceeded {
			updates["remote_access_status"] = "ready"
			updates["wire_guard_last_error"] = nil
		} else if job.Status == StatusFailed {
			updates["remote_access_status"] = "failed"
			updates["wire_guard_last_error"] = message
		}
	case OperationRemoveRemoteAccess:
		if job.Status == StatusSucceeded {
			updates["remote_access_status"] = "disabled"
			updates["remote_web_port"] = nil
			updates["remote_winbox_port"] = nil
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
	if err := s.db.Model(&routers.Router{}).Where("id = ?", job.RouterID).Updates(updates).Error; err != nil {
		return err
	}
	if job.Operation == OperationConfigureRouter && job.Status == StatusSucceeded {
		return s.db.Model(&WireGuardJob{}).
			Where(
				"router_id = ? AND operation = ? AND id <> ? AND status IN ?",
				job.RouterID,
				OperationConfigureRouter,
				job.ID,
				[]string{StatusQueued, StatusClaimed, StatusApplying, StatusRetrying},
			).
			Updates(map[string]any{
				"status":       StatusCancelled,
				"completed_at": now,
				"locked_by":    "",
				"locked_at":    nil,
				"last_error":   "cancelled because router configuration already succeeded",
			}).Error
	}
	return nil
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

func hostOnly(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "/") {
		return strings.TrimSpace(strings.SplitN(value, "/", 2)[0])
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if strings.Contains(value, ":") && !strings.Contains(value, "::") {
		host, _, found := strings.Cut(value, ":")
		if found && host != "" {
			return host
		}
	}
	return strings.Trim(value, "[]")
}

func normalizeProvisioningBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return "http://localhost:8080/api/v1/provisioning"
	}
	lower := strings.ToLower(baseURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "https://" + baseURL
	}
	return baseURL
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func ptrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Service) routerAPIPassword(router routers.Router) string {
	if router.APIPasswordEncrypted != nil {
		value := strings.TrimSpace(*router.APIPasswordEncrypted)
		if strings.HasPrefix(value, "encrypted-placeholder:") {
			return strings.TrimPrefix(value, "encrypted-placeholder:")
		}
	}
	return s.cfg.RouterAPIPassword
}
