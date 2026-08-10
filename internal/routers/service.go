package routers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/mikrotik"
	"github.com/noblifi/noblifi/backend/internal/placeholders"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"gorm.io/gorm"
)

type Service struct {
	repo                    *Repository
	cfg                     config.Config
	cleanup                 WireGuardCleanupQueuer
	remoteAccess            RemoteAccessQueuer
	serverPublicKeyResolver WireGuardServerPublicKeyResolver
}

type WireGuardCleanupQueuer interface {
	QueuePeerRemoval(router Router) error
}

type RemoteAccessQueuer interface {
	QueueRemoteAccess(router Router) error
}

type WireGuardServerPublicKeyResolver interface {
	ActiveServerPublicKey() (string, error)
}

func NewService(repo *Repository, cfg config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

func (s *Service) SetWireGuardCleanup(cleanup WireGuardCleanupQueuer) {
	s.cleanup = cleanup
}

func (s *Service) SetRemoteAccessQueuer(remoteAccess RemoteAccessQueuer) {
	s.remoteAccess = remoteAccess
}

func (s *Service) SetWireGuardServerPublicKeyResolver(resolver WireGuardServerPublicKeyResolver) {
	s.serverPublicKeyResolver = resolver
}

func (s *Service) Create(input CreateRouterInput) (Router, error) {
	return s.CreateForUser(input, AuthUser{})
}

func (s *Service) CreateForUser(input CreateRouterInput, user AuthUser) (Router, error) {
	if user.ID != uuid.Nil && user.Role != "superadmin" {
		if user.AccountStatus != "approved" {
			return Router{}, errors.New("account is pending superadmin approval")
		}
		var count int64
		if err := s.repo.db.Model(&Router{}).Where("owner_user_id = ? AND deleted_at IS NULL", user.ID).Count(&count).Error; err != nil {
			return Router{}, err
		}
		if count >= int64(user.RouterLimit) {
			return Router{}, fmt.Errorf("router limit reached (%d). Request an increase from the superadmin", user.RouterLimit)
		}
	}
	expires := time.Now().Add(time.Duration(s.cfg.ProvisioningTokenTTLHour) * time.Hour)
	var siteName *string
	if strings.TrimSpace(input.SiteName) != "" {
		value := strings.TrimSpace(input.SiteName)
		siteName = &value
	}
	expectedModel := strings.TrimSpace(input.ExpectedModel)
	if expectedModel == "" {
		expectedModel = strings.TrimSpace(input.Model)
	}
	var expectedModelPtr *string
	if expectedModel != "" {
		expectedModelPtr = &expectedModel
	}
	router := Router{
		Name:                input.Name,
		OwnerUserID:         userIDPtr(user.ID),
		SiteName:            siteName,
		ExpectedModel:       expectedModelPtr,
		Status:              "pending",
		ClaimToken:          randomToken(),
		ClaimTokenExpiresAt: &expires,
	}
	err := s.repo.Create(&router)
	if err != nil {
		return router, err
	}
	profile := s.defaultNetworkProfile(router.ID, router.Name)
	if portalName := firstNonEmpty(user.PortalName, user.Name); portalName != "" && user.Role != "superadmin" {
		profile.HotspotPortalName = portalName
	}
	if err := s.repo.CreateNetworkProfile(&profile); err != nil {
		return router, err
	}
	return router, nil
}

func (s *Service) List() ([]Router, error) {
	return s.repo.List()
}

func (s *Service) ListForUser(user AuthUser) ([]Router, error) {
	if user.Role == "superadmin" {
		return s.repo.List()
	}
	if user.ID == uuid.Nil {
		return nil, errors.New("missing account")
	}
	return s.repo.ListByOwner(user.ID)
}

func (s *Service) Find(id uuid.UUID) (Router, error) {
	return s.repo.Find(id)
}

func (s *Service) RequestDelete(routerID uuid.UUID) (Router, error) {
	return s.RequestDeleteWithConfirmation(routerID, AuthUser{}, "", "")
}

func (s *Service) RequestDeleteWithConfirmation(routerID uuid.UUID, user AuthUser, typedName, code string) (Router, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return router, err
	}
	if user.ID != uuid.Nil {
		if user.Role != "superadmin" && (router.OwnerUserID == nil || *router.OwnerUserID != user.ID) {
			return router, errors.New("router does not belong to this account")
		}
		if strings.TrimSpace(typedName) != router.Name {
			return router, fmt.Errorf("type %q to confirm router deletion", router.Name)
		}
		if strings.TrimSpace(code) == "" {
			return router, errors.New("email confirmation code is required")
		}
	}
	if router.DeletedAt != nil {
		return router, nil
	}
	now := time.Now().UTC()
	router.DeleteRequestedAt = &now
	router.Status = "delete_requested"
	router.ProvisioningStatus = "delete_requested"
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" && s.cleanup != nil {
		router.WireGuardPeerStatus = "removal_queued"
		router.ProvisioningStatus = "removal_queued"
		if err := s.cleanup.QueuePeerRemoval(router); err != nil {
			msg := err.Error()
			router.ProvisioningError = &msg
			router.WireGuardLastError = &msg
			_ = s.repo.Save(&router)
			return router, err
		}
	} else {
		router.Status = "deleted"
		router.ProvisioningStatus = "deleted"
		router.DeletedAt = &now
	}
	err = s.repo.Save(&router)
	return router, err
}

func userIDPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, ErrNotFound)
}

func (s *Service) NetworkProfile(routerID uuid.UUID) (RouterNetworkProfile, error) {
	profile, err := s.repo.NetworkProfile(routerID)
	if err == nil {
		s.normalizeNetworkProfile(&profile)
		return profile, nil
	}
	router, findErr := s.repo.Find(routerID)
	if findErr != nil {
		return RouterNetworkProfile{}, findErr
	}
	profile = s.defaultNetworkProfile(routerID, router.Name)
	return profile, s.repo.CreateNetworkProfile(&profile)
}

func (s *Service) UpdateNetworkProfile(routerID uuid.UUID, input RouterNetworkProfile) (RouterNetworkProfile, error) {
	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return profile, err
	}
	mergeNetworkProfile(&profile, input)
	err = s.repo.SaveNetworkProfile(&profile)
	return profile, err
}

func (s *Service) RegenerateClaimToken(id uuid.UUID) (Router, error) {
	router, err := s.repo.Find(id)
	if err != nil {
		return router, err
	}
	expires := time.Now().Add(time.Duration(s.cfg.ProvisioningTokenTTLHour) * time.Hour)
	router.ClaimToken = randomToken()
	router.ClaimTokenExpiresAt = &expires
	err = s.repo.Save(&router)
	return router, err
}

func (s *Service) SavePortAssignments(routerID uuid.UUID, inputs []portprofiles.Assignment) error {
	if err := portprofiles.Validate(inputs); err != nil {
		return err
	}
	if err := s.validateAssignablePorts(routerID, inputs); err != nil {
		return err
	}
	assignments := make([]RouterPortAssignment, 0, len(inputs))
	for _, input := range inputs {
		assignments = append(assignments, RouterPortAssignment{
			RouterID:      routerID,
			InterfaceName: input.Name(),
			Role:          input.Role,
		})
	}
	if err := s.repo.ReplacePortAssignments(routerID, assignments); err != nil {
		return err
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return err
	}
	session.CurrentStep = "preview"
	return s.repo.SaveSetupSession(&session)
}

func (s *Service) validateAssignablePorts(routerID uuid.UUID, inputs []portprofiles.Assignment) error {
	interfaces, err := s.repo.Interfaces(routerID)
	if err != nil {
		return err
	}
	byName := map[string]RouterInterface{}
	for _, iface := range interfaces {
		byName[iface.Name] = iface
	}
	for _, input := range inputs {
		role := strings.TrimSpace(input.Role)
		if role == "DISABLED" {
			continue
		}
		iface, ok := byName[input.Name()]
		if !ok {
			return fmt.Errorf("interface %s was not discovered on this MikroTik", input.Name())
		}
		if iface.Disabled && (role == "WAN" || role == "HOTSPOT_LAN") {
			return fmt.Errorf("interface %s is disabled and cannot be used for %s", iface.Name, role)
		}
		if isVirtualInterface(iface) && (role == "WAN" || role == "HOTSPOT_LAN") {
			return fmt.Errorf("interface %s is %s and cannot be used for %s; select a physical port like ether1", iface.Name, interfaceType(iface), role)
		}
	}
	return nil
}

func isVirtualInterface(iface RouterInterface) bool {
	typeName := strings.ToLower(interfaceType(iface))
	name := strings.ToLower(iface.Name)
	return strings.Contains(typeName, "bridge") ||
		strings.Contains(typeName, "loopback") ||
		strings.Contains(typeName, "tunnel") ||
		strings.Contains(typeName, "wireguard") ||
		typeName == "wg" ||
		strings.Contains(name, "bridge") ||
		strings.HasPrefix(name, "br-") ||
		strings.Contains(name, "wireguard") ||
		strings.HasPrefix(name, "wg") ||
		strings.Contains(name, "-wg")
}

func interfaceType(iface RouterInterface) string {
	if iface.Type == nil || strings.TrimSpace(*iface.Type) == "" {
		return "unknown"
	}
	return *iface.Type
}

func (s *Service) SaveRemoteAccess(routerID uuid.UUID, input RemoteAccessInput) (RouterSetupSession, error) {
	method := strings.TrimSpace(input.RemoteAccessMethod)
	if method != "bootstrap" && method != "direct_api" && method != "wireguard" {
		return RouterSetupSession{}, errors.New("remote_access_method must be bootstrap, direct_api, or wireguard")
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return RouterSetupSession{}, err
	}
	if method == "direct_api" {
		if input.Host == "" || input.APIPort == 0 || input.Username == "" || input.Password == "" {
			return RouterSetupSession{}, errors.New("host, api_port, username, and password are required for direct API access")
		}
		if err := TestRouterConnection(input.Host, input.APIPort, input.Username, input.Password); err != nil {
			return RouterSetupSession{}, err
		}
		router.ManagementIP = &input.Host
		router.APIUsername = &input.Username
		encrypted := "encrypted-placeholder:" + input.Password
		router.APIPasswordEncrypted = &encrypted
		if err := s.repo.Save(&router); err != nil {
			return RouterSetupSession{}, err
		}
	}
	if method == "wireguard" {
		if _, err := s.PrepareWireGuard(routerID); err != nil {
			return RouterSetupSession{}, err
		}
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return session, err
	}
	session.RemoteAccessMethod = &method
	session.CurrentStep = "method"
	return session, s.repo.SaveSetupSession(&session)
}

func TestRouterConnection(host string, apiPort int, username, password string) error {
	client := mikrotik.NewClient(host, username, password).WithPort(apiPort)
	conn, err := client.DialAndLogin()
	if err != nil {
		return err
	}
	return conn.Close()
}

func (s *Service) RemoteAccessDetails(routerID uuid.UUID) (RemoteAccessDetails, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return RemoteAccessDetails{}, err
	}
	address := s.managementAddress(router)
	if address == "" {
		return RemoteAccessDetails{}, errors.New("router management address is not configured")
	}
	method := "direct_api"
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		method = "wireguard"
	}
	host := publicHostOnly(s.cfg.RemoteAccessHost)
	if host != "" && router.RemoteWebPort != nil {
		webURL := fmt.Sprintf("http://%s:%d/webfig/", host, *router.RemoteWebPort)
		return RemoteAccessDetails{
			RouterID:        router.ID,
			Address:         fmt.Sprintf("%s:%d", host, *router.RemoteWebPort),
			APIAddress:      fmt.Sprintf("%s:8728", address),
			WinboxAddress:   publicPortAddress(host, router.RemoteWinboxPort),
			WebURL:          webURL,
			SecureWebURL:    webURL,
			Method:          "vpn_forward",
			WireGuardStatus: router.WireGuardStatus,
			Ready:           router.RemoteAccessStatus == "ready",
		}, nil
	}
	return RemoteAccessDetails{
		RouterID:        router.ID,
		Address:         address,
		APIAddress:      fmt.Sprintf("%s:8728", address),
		WinboxAddress:   fmt.Sprintf("%s:8291", address),
		WebURL:          "http://" + address + "/",
		SecureWebURL:    "https://" + address + "/",
		Method:          method,
		WireGuardStatus: router.WireGuardStatus,
		Ready:           address != "",
	}, nil
}

func (s *Service) EnableVPNRemoteAccess(routerID uuid.UUID) (RemoteAccessDetails, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return RemoteAccessDetails{}, err
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		if _, err := s.PrepareWireGuard(routerID); err != nil {
			return RemoteAccessDetails{}, err
		}
		router, err = s.repo.Find(routerID)
		if err != nil {
			return RemoteAccessDetails{}, err
		}
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return RemoteAccessDetails{}, errors.New("WireGuard tunnel IP is required before remote access can be published")
	}
	webPort, winboxPort := s.remotePortsForRouter(router)
	router.RemoteWebPort = &webPort
	router.RemoteWinboxPort = &winboxPort
	router.RemoteAccessStatus = "queued"
	if err := s.repo.Save(&router); err != nil {
		return RemoteAccessDetails{}, err
	}
	if s.remoteAccess != nil {
		if err := s.remoteAccess.QueueRemoteAccess(router); err != nil {
			return RemoteAccessDetails{}, err
		}
	}
	return s.RemoteAccessDetails(routerID)
}

func (s *Service) TestConnection(routerID uuid.UUID) (ConnectionTestResult, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return ConnectionTestResult{}, err
	}
	address := s.managementAddress(router)
	if isWireGuardManagementAddress(address) {
		if router.WireGuardLastHandshakeAt == nil {
			return ConnectionTestResult{
				Success: false,
				Message: "WireGuard tunnel is not connected yet; waiting for the MikroTik to handshake with the VPS agent.",
			}, nil
		}
		age := time.Since(*router.WireGuardLastHandshakeAt)
		if age > 10*time.Minute {
			return ConnectionTestResult{
				Success: false,
				Message: fmt.Sprintf("WireGuard tunnel last handshook %s ago; the VPS agent must reconnect before RouterOS API checks can run.", age.Round(time.Second)),
			}, nil
		}
		now := time.Now().UTC()
		router.LastSeenAt = &now
		if router.Status == "" || router.Status == "pending" || router.Status == "provisioning" {
			router.Status = "online"
		}
		_ = s.repo.Save(&router)
		return ConnectionTestResult{
			Success: true,
			Message: "WireGuard tunnel is connected. RouterOS API checks for this private address run from the VPS agent, not App Engine.",
		}, nil
	}
	client, err := s.routerClient(router)
	if err != nil {
		return ConnectionTestResult{}, err
	}
	if _, err := client.Command("/system/resource/print", nil); err != nil {
		return ConnectionTestResult{Success: false, Message: err.Error()}, err
	}
	now := time.Now().UTC()
	router.LastSeenAt = &now
	router.Status = "online"
	_ = s.repo.Save(&router)
	return ConnectionTestResult{Success: true, Message: "RouterOS API connection succeeded"}, nil
}

// CollectTelemetry pulls CPU load, uptime, memory, interface state, and
// active hotspot user count directly from RouterOS over the router's
// configured management address (WireGuard tunnel IP or direct API host),
// then persists the values onto the Router row so the dashboard can read a
// cached snapshot without hitting the router on every page load.
//
// On any failure to reach or query the router, the error is recorded on
// TelemetryLastError (without touching the last-known-good values) so the
// dashboard can surface "last update failed" instead of silently going
// stale with no explanation.
func (s *Service) CollectTelemetry(routerID uuid.UUID) (RouterTelemetry, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return RouterTelemetry{}, err
	}
	client, err := s.routerClient(router)
	if err != nil {
		s.recordTelemetryError(router, err)
		return RouterTelemetry{}, err
	}

	resourceRows, err := client.Command("/system/resource/print", nil)
	if err != nil {
		s.recordTelemetryError(router, err)
		return RouterTelemetry{}, err
	}
	identityRows, _ := client.Command("/system/identity/print", nil)
	interfaceRows, _ := client.Command("/interface/print", nil)
	activeRows, _ := client.Command("/ip/hotspot/active/print", nil)

	resource := firstRow(resourceRows)
	identity := firstRow(identityRows)
	interfaces := make([]RouterInterface, 0, len(interfaceRows))
	for _, row := range interfaceRows {
		name := row["=name"]
		if name == "" {
			continue
		}
		iface := RouterInterface{
			RouterID:     routerID,
			Name:         name,
			Running:      parseRouterOSAPIBool(row["=running"]),
			Disabled:     parseRouterOSAPIBool(row["=disabled"]),
			DiscoveredAt: time.Now().UTC(),
		}
		if value := row["=type"]; value != "" {
			iface.Type = &value
		}
		if value := row["=mac-address"]; value != "" {
			iface.MacAddress = &value
		}
		interfaces = append(interfaces, iface)
	}
	if len(interfaces) > 0 {
		_ = s.repo.ReplaceInterfaces(routerID, interfaces)
	}

	now := time.Now().UTC()
	if value := resource["=version"]; value != "" {
		router.RouterOSVersion = &value
	}
	if value := firstNonEmpty(resource["=board-name"], resource["=platform"]); value != "" {
		router.Model = &value
	}

	cpuLoad := resource["=cpu-load"]
	uptime := resource["=uptime"]
	freeMemory := resource["=free-memory"]
	totalMemory := resource["=total-memory"]
	activeUsers := len(activeRows)

	router.CPULoad = &cpuLoad
	router.Uptime = &uptime
	router.FreeMemory = &freeMemory
	router.TotalMemory = &totalMemory
	router.ActiveHotspotUsers = &activeUsers
	router.TelemetryUpdatedAt = &now
	router.TelemetryLastError = nil

	router.LastSeenAt = &now
	router.Status = "online"
	if err := s.repo.Save(&router); err != nil {
		return RouterTelemetry{}, err
	}

	return RouterTelemetry{
		RouterID:           routerID,
		Name:               router.Name,
		Identity:           identity["=name"],
		Model:              firstNonEmpty(resource["=board-name"], resource["=platform"]),
		RouterOSVersion:    resource["=version"],
		Uptime:             uptime,
		CPULoad:            cpuLoad,
		FreeMemory:         freeMemory,
		TotalMemory:        totalMemory,
		FreeHDD:            resource["=free-hdd-space"],
		TotalHDD:           resource["=total-hdd-space"],
		Architecture:       resource["=architecture-name"],
		BoardName:          resource["=board-name"],
		ActiveHotspotUsers: activeUsers,
		Interfaces:         interfaces,
		LastSeenAt:         &now,
	}, nil
}

// recordTelemetryError saves the failure reason onto the router row without
// disturbing the last successfully collected values, so a temporarily
// unreachable router shows "last update failed X ago" instead of blank or
// stale-but-unexplained numbers.
func (s *Service) recordTelemetryError(router Router, err error) {
	msg := err.Error()
	router.TelemetryLastError = &msg
	_ = s.repo.Save(&router)
}

// CollectTelemetryForAllRouters refreshes telemetry for every non-deleted
// router that has a reachable management address. It is intended to be
// called on a fixed interval by App Engine cron (see cron.yaml) rather than
// by an end user, so the dashboard reflects a recent snapshot without anyone
// needing to click "Collect".
//
// Each router's collection is bounded by perRouterTimeout so a single
// unreachable or slow router cannot stall the whole batch; a router that
// times out simply keeps whatever value CollectTelemetry manages to persist
// (or its previous last-known-good values) and is picked up again next run.
func (s *Service) CollectTelemetryForAllRouters() {
	const perRouterTimeout = 8 * time.Second

	routers, err := s.repo.List()
	if err != nil {
		return
	}

	for _, router := range routers {
		if router.DeletedAt != nil {
			continue
		}
		if s.managementAddress(router) == "" {
			continue
		}
		if isWireGuardManagementAddress(s.managementAddress(router)) {
			// Private WireGuard tunnel routers are collected by the VPS agent.
			// App Engine cannot route to 10.77.0.x, and recording that here
			// would overwrite a healthy agent-supplied telemetry snapshot.
			continue
		}

		routerID := router.ID
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = s.CollectTelemetry(routerID)
		}()

		select {
		case <-done:
		case <-time.After(perRouterTimeout):
			s.recordTelemetryError(router, fmt.Errorf("telemetry collection timed out after %s", perRouterTimeout))
			// The goroutine may still finish and persist fresh values later; the
			// batch does not block the rest of the routers on this one.
		}
	}
}

func isWireGuardManagementAddress(address string) bool {
	address = hostOnly(strings.TrimSpace(address))
	return strings.HasPrefix(address, "10.77.")
}

func (s *Service) RenameRouter(routerID uuid.UUID, name string) (Router, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Router{}, errors.New("router name is required")
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return router, err
	}
	client, err := s.routerClient(router)
	if err != nil {
		return router, err
	}
	if _, err := client.Command("/system/identity/set", map[string]string{"=name": name}); err != nil {
		return router, err
	}
	router.Name = name
	if err := s.repo.Save(&router); err != nil {
		return router, err
	}
	return router, nil
}

func (s *Service) UpdateRouterAdminPassword(routerID uuid.UUID, password string) error {
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return err
	}
	username := firstNonEmpty(ptrValue(router.APIUsername), s.cfg.RouterAPIUsername)
	client, err := s.routerClient(router)
	if err != nil {
		return err
	}
	_, err = client.Command("/user/set", map[string]string{
		"=numbers":  username,
		"=password": password,
	})
	if err != nil {
		return err
	}
	encrypted := "encrypted-placeholder:" + password
	router.APIPasswordEncrypted = &encrypted
	return s.repo.Save(&router)
}

func (s *Service) RebootRouter(routerID uuid.UUID) error {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return err
	}
	client, err := s.routerClient(router)
	if err != nil {
		return err
	}
	_, err = client.Command("/system/reboot", nil)
	return err
}

func (s *Service) routerClient(router Router) (*mikrotik.Client, error) {
	address := s.managementAddress(router)
	if address == "" {
		return nil, errors.New("router management address is not configured")
	}
	username := firstNonEmpty(ptrValue(router.APIUsername), s.cfg.RouterAPIUsername)
	password := s.routerAPIPassword(router)
	if username == "" || password == "" {
		return nil, errors.New("router API credentials are not configured")
	}
	return mikrotik.NewClient(address, username, password).WithPort(8728), nil
}

func (s *Service) managementAddress(router Router) string {
	if router.ManagementIP != nil && strings.TrimSpace(*router.ManagementIP) != "" {
		return hostOnly(*router.ManagementIP)
	}
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		return hostOnly(*router.WireGuardTunnelIP)
	}
	return ""
}

func (s *Service) routerAPIPassword(router Router) string {
	if router.APIPasswordEncrypted != nil {
		value := strings.TrimSpace(*router.APIPasswordEncrypted)
		if strings.HasPrefix(value, "encrypted-placeholder:") {
			return strings.TrimPrefix(value, "encrypted-placeholder:")
		}
	}
	return s.cfg.RouterAPIPassword
}

func (s *Service) remotePortsForRouter(router Router) (int, int) {
	if router.RemoteWebPort != nil && router.RemoteWinboxPort != nil {
		return *router.RemoteWebPort, *router.RemoteWinboxPort
	}
	offset := 0
	if router.WireGuardTunnelIP != nil {
		parts := strings.Split(hostOnly(*router.WireGuardTunnelIP), ".")
		if len(parts) == 4 {
			var parsed int
			_, _ = fmt.Sscanf(parts[3], "%d", &parsed)
			offset = parsed
		}
	}
	if offset <= 0 {
		offset = int(router.ID[15]) + 1
	}
	return s.cfg.RemoteAccessWebPortBase + offset, s.cfg.RemoteAccessWinboxPortBase + offset
}

func publicPortAddress(host string, port *int) string {
	host = publicHostOnly(host)
	if host == "" || port == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", host, *port)
}

func publicHostOnly(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimRight(value, "/")
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
}

func hostOnly(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
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

func firstRow(rows []map[string]string) map[string]string {
	if len(rows) == 0 {
		return map[string]string{}
	}
	return rows[0]
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

func parseRouterOSAPIBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "yes" || value == "1"
}

func (s *Service) SaveMethod(routerID uuid.UUID, input MethodInput) (RouterSetupSession, error) {
	method := strings.TrimSpace(input.ConfigurationMethod)
	if method != "automatic" && method != "manual" {
		return RouterSetupSession{}, errors.New("configuration_method must be automatic or manual")
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return session, err
	}
	session.ConfigurationMethod = &method
	if method == "automatic" {
		session.CurrentStep = "topology"
	} else {
		session.CurrentStep = "manual"
	}
	return session, s.repo.SaveSetupSession(&session)
}

func (s *Service) Interfaces(routerID uuid.UUID) ([]RouterInterface, error) {
	interfaces, err := s.repo.Interfaces(routerID)
	if err != nil {
		return nil, err
	}
	if len(interfaces) > 0 {
		return interfaces, nil
	}
	return interfaces, nil
}

func (s *Service) BootstrapScript(routerID uuid.UUID) (string, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return "", err
	}
	return bootstrapScript(router.ClaimToken, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) ConfigInstallCommand(routerID uuid.UUID) (string, error) {
	if _, err := s.ConfigPreview(routerID); err != nil {
		return "", err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return "", err
	}
	return configInstallCommand(router.ClaimToken, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) HotspotInstallCommand(routerID uuid.UUID) (string, error) {
	if err := s.prepareWireGuardForInstall(routerID); err != nil {
		return "", err
	}
	if _, err := s.ConfigPreview(routerID); err != nil {
		return "", err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return "", err
	}
	return hotspotInstallCommand(router.ClaimToken, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) prepareWireGuardForInstall(routerID uuid.UUID) error {
	cfg := s.wireGuardConfig()
	if !cfg.WireGuardEnabled {
		return nil
	}
	if err := ValidateWireGuardConfig(cfg); err != nil {
		return err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return err
	}
	if !routerSupportsWireGuard(router.RouterOSVersion) {
		return nil
	}
	_, err = s.PrepareWireGuard(routerID)
	return err
}

func (s *Service) ConfigPreview(routerID uuid.UUID) (ConfigPreview, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return ConfigPreview{}, err
	}
	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{InterfaceName: assignment.InterfaceName, Role: assignment.Role})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}
	if err := portprofiles.Validate(assignments); err != nil {
		return ConfigPreview{}, err
	}
	if err := s.validateAssignablePorts(routerID, assignments); err != nil {
		return ConfigPreview{}, err
	}
	options, err := s.renderOptionsForRouter(routerID)
	if err != nil {
		return ConfigPreview{}, err
	}
	options.LoginPageURL = hotspotLoginURL(router.ClaimToken, s.cfg.ProvisioningBaseURL)
	options.HotspotSupportBaseURL = hotspotSupportURL(router.ClaimToken, s.cfg.ProvisioningBaseURL)
	script, err := portprofiles.RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		return ConfigPreview{}, err
	}
	return ConfigPreview{Summary: portprofiles.BuildSummary(assignments), Script: script}, nil
}

func (s *Service) Deploy(routerID uuid.UUID) (map[string]string, error) {
	preview, err := s.ConfigPreview(routerID)
	if err != nil {
		return nil, err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(preview.Summary)
	log := RouterConfigLog{
		RouterID:       routerID,
		Action:         "deploy",
		Status:         "queued",
		RequestPayload: payload,
	}
	if err := s.repo.CreateConfigLog(&log); err != nil {
		return nil, err
	}
	router.Status = "provisioning"
	if err := s.repo.Save(&router); err != nil {
		return nil, err
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return nil, err
	}
	session.CurrentStep = "deploy_queued"
	session.DeploymentStatus = "queued"
	if err := s.repo.SaveSetupSession(&session); err != nil {
		return nil, err
	}
	return map[string]string{"message": "Configuration deployment queued", "status": "queued"}, nil
}

func randomToken() string {
	left := make([]byte, 2)
	right := make([]byte, 2)
	if _, err := rand.Read(left); err != nil {
		return "NOB-" + strings.ToUpper(uuid.NewString()[0:4]) + "-" + strings.ToUpper(uuid.NewString()[0:4])
	}
	if _, err := rand.Read(right); err != nil {
		return "NOB-" + strings.ToUpper(uuid.NewString()[0:4]) + "-" + strings.ToUpper(uuid.NewString()[0:4])
	}
	return fmt.Sprintf("NOB-%s-%s", strings.ToUpper(hex.EncodeToString(left)), strings.ToUpper(hex.EncodeToString(right)))
}

func bootstrapScript(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	bootstrapURL := baseURL + "/bootstrap/" + token

	return routerOSFetchImportCommand(bootstrapURL, fetchMode, "noblifi-bootstrap.rsc") + `

# If the NobliFi bootstrap fails because this MikroTik is still below RouterOS 7,
# use the commands below to upgrade first, then rerun the NobliFi bootstrap command above.
# If you accidentally typed "stem reboot", run the correct command:
/system reboot

# After the router reconnects, verify RouterBOARD firmware:
/system routerboard print

# Then upgrade RouterOS 6.x to the RouterOS 7 intermediate release:
/system package update set channel=upgrade
/system package update check-for-updates
/system package update install

# After the router reboots, verify RouterOS is now 7.x:
/system resource print

# Do not rerun NobliFi bootstrap until /system resource print confirms RouterOS 7.x.`
}

func configInstallCommand(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	configURL := baseURL + "/config/" + token

	return routerOSFetchImportCommand(configURL, fetchMode, "noblifi-config.rsc")
}

func hotspotInstallCommand(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	installURL := baseURL + "/install/" + token

	return routerOSFetchImportCommand(installURL, fetchMode, "noblifi-install.rsc")
}

func routerOSFetchImportCommand(url, mode, filename string) string {
	return fmt.Sprintf(`/tool fetch url="%s" mode=%s dst-path="%s"; :delay 2s; /import file-name="%s"; :delay 1s; /file remove "%s"`, url, mode, filename, filename, filename)
}

func hotspotLoginURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-login/" + token
}

func hotspotSupportURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-support/" + token
}

func legacyRandomToken() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString()
	}
	return hex.EncodeToString(bytes)
}

func normalizeProvisioningBaseURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	baseURL = strings.TrimRight(baseURL, "/")

	if baseURL == "" {
		return "http://localhost:8080/api/v1/provisioning"
	}

	lower := strings.ToLower(baseURL)

	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "https://" + baseURL
	}

	return baseURL
}

func provisioningFetchMode(baseURL string) string {
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		return "https"
	}

	return "http"
}

func renderOptions(cfg config.Config) portprofiles.RenderOptions {
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
		HotspotTemplateKey:  "clean",
		WalledGardenHosts:   cfg.HotspotWalledGardenHosts,
		DisableWWWService:   cfg.DisableWWWService,
		EnableAPIService:    cfg.EnableAPIService,
		EnableAPISSLService: cfg.EnableAPISSLService,
	}
}

func (s *Service) renderOptionsForRouter(routerID uuid.UUID) (portprofiles.RenderOptions, error) {
	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return portprofiles.RenderOptions{}, err
	}
	return profile.RenderOptions(), nil
}

func (s *Service) normalizeNetworkProfile(profile *RouterNetworkProfile) {
	NormalizeNetworkProfile(profile, s.cfg)
}

func NormalizeNetworkProfile(profile *RouterNetworkProfile, cfg config.Config) {
	if placeholders.Is(profile.RadiusServer) {
		profile.RadiusServer = cfg.RadiusServer
	}
	if placeholders.Is(profile.RadiusSecret) {
		profile.RadiusSecret = cfg.RadiusSecret
	}
	if placeholders.Is(profile.APIPassword) {
		profile.APIPassword = cfg.RouterAPIPassword
	}
}
func (s *Service) defaultNetworkProfile(routerID uuid.UUID, routerName string) RouterNetworkProfile {
	return RouterNetworkProfile{
		RouterID:            routerID,
		Name:                routerName + " Network Profile",
		RadiusServer:        s.cfg.RadiusServer,
		RadiusSecret:        s.cfg.RadiusSecret,
		RouterIdentity:      s.cfg.RouterIdentityPrefix + "-" + sanitizeIdentity(routerName),
		APIUsername:         s.cfg.RouterAPIUsername,
		APIPassword:         s.cfg.RouterAPIPassword,
		HotspotBridge:       s.cfg.HotspotBridgeName,
		StaffBridge:         s.cfg.StaffBridgeName,
		POSBridge:           s.cfg.POSBridgeName,
		CCTVBridge:          s.cfg.CCTVBridgeName,
		HotspotSubnet:       s.cfg.HotspotSubnetCIDR,
		HotspotGateway:      s.cfg.HotspotGatewayCIDR,
		HotspotPool:         s.cfg.HotspotPoolRange,
		StaffSubnet:         s.cfg.StaffSubnetCIDR,
		StaffGateway:        s.cfg.StaffGatewayCIDR,
		StaffPool:           s.cfg.StaffPoolRange,
		POSSubnet:           s.cfg.POSSubnetCIDR,
		POSGateway:          s.cfg.POSGatewayCIDR,
		POSPool:             s.cfg.POSPoolRange,
		CCTVSubnet:          s.cfg.CCTVSubnetCIDR,
		CCTVGateway:         s.cfg.CCTVGatewayCIDR,
		CCTVPool:            s.cfg.CCTVPoolRange,
		HotspotDNSName:      s.cfg.HotspotDNSName,
		HotspotPortalName:   s.cfg.HotspotPortalName,
		HotspotTemplateKey:  "clean",
		WANMode:             "dhcp",
		DisableWWWService:   s.cfg.DisableWWWService,
		EnableAPIService:    s.cfg.EnableAPIService,
		EnableAPISSLService: s.cfg.EnableAPISSLService,
	}
}

func (p RouterNetworkProfile) RenderOptions() portprofiles.RenderOptions {
	return portprofiles.RenderOptions{
		RadiusServer:        p.RadiusServer,
		RadiusSecret:        p.RadiusSecret,
		RouterIdentity:      p.RouterIdentity,
		APIUsername:         p.APIUsername,
		APIPassword:         p.APIPassword,
		HotspotBridge:       p.HotspotBridge,
		StaffBridge:         p.StaffBridge,
		POSBridge:           p.POSBridge,
		CCTVBridge:          p.CCTVBridge,
		HotspotSubnet:       p.HotspotSubnet,
		HotspotGateway:      p.HotspotGateway,
		HotspotPool:         p.HotspotPool,
		StaffSubnet:         p.StaffSubnet,
		StaffGateway:        p.StaffGateway,
		StaffPool:           p.StaffPool,
		POSSubnet:           p.POSSubnet,
		POSGateway:          p.POSGateway,
		POSPool:             p.POSPool,
		CCTVSubnet:          p.CCTVSubnet,
		CCTVGateway:         p.CCTVGateway,
		CCTVPool:            p.CCTVPool,
		HotspotDNSName:      p.HotspotDNSName,
		HotspotPortalName:   p.HotspotPortalName,
		HotspotTemplateKey:  p.HotspotTemplateKey,
		DisableWWWService:   p.DisableWWWService,
		EnableAPIService:    p.EnableAPIService,
		EnableAPISSLService: p.EnableAPISSLService,
	}
}

func mergeNetworkProfile(profile *RouterNetworkProfile, input RouterNetworkProfile) {
	if input.Name != "" {
		profile.Name = input.Name
	}
	if input.RadiusServer != "" {
		profile.RadiusServer = input.RadiusServer
	}
	if input.RadiusSecret != "" {
		profile.RadiusSecret = input.RadiusSecret
	}
	if input.RouterIdentity != "" {
		profile.RouterIdentity = input.RouterIdentity
	}
	if input.APIUsername != "" {
		profile.APIUsername = input.APIUsername
	}
	if input.APIPassword != "" {
		profile.APIPassword = input.APIPassword
	}
	if input.HotspotBridge != "" {
		profile.HotspotBridge = input.HotspotBridge
	}
	if input.StaffBridge != "" {
		profile.StaffBridge = input.StaffBridge
	}
	if input.POSBridge != "" {
		profile.POSBridge = input.POSBridge
	}
	if input.CCTVBridge != "" {
		profile.CCTVBridge = input.CCTVBridge
	}
	if input.HotspotSubnet != "" {
		profile.HotspotSubnet = input.HotspotSubnet
	}
	if input.HotspotGateway != "" {
		profile.HotspotGateway = input.HotspotGateway
	}
	if input.HotspotPool != "" {
		profile.HotspotPool = input.HotspotPool
	}
	if input.StaffSubnet != "" {
		profile.StaffSubnet = input.StaffSubnet
	}
	if input.StaffGateway != "" {
		profile.StaffGateway = input.StaffGateway
	}
	if input.StaffPool != "" {
		profile.StaffPool = input.StaffPool
	}
	if input.POSSubnet != "" {
		profile.POSSubnet = input.POSSubnet
	}
	if input.POSGateway != "" {
		profile.POSGateway = input.POSGateway
	}
	if input.POSPool != "" {
		profile.POSPool = input.POSPool
	}
	if input.CCTVSubnet != "" {
		profile.CCTVSubnet = input.CCTVSubnet
	}
	if input.CCTVGateway != "" {
		profile.CCTVGateway = input.CCTVGateway
	}
	if input.CCTVPool != "" {
		profile.CCTVPool = input.CCTVPool
	}
	if input.HotspotDNSName != "" {
		profile.HotspotDNSName = input.HotspotDNSName
	}
	if input.HotspotPortalName != "" {
		profile.HotspotPortalName = input.HotspotPortalName
	}
	if input.HotspotTemplateKey != "" {
		profile.HotspotTemplateKey = input.HotspotTemplateKey
	}
	if input.WANMode != "" {
		profile.WANMode = input.WANMode
	}
	if input.PPPoEUsername != nil {
		profile.PPPoEUsername = input.PPPoEUsername
	}
	if input.PPPoEPassword != nil {
		profile.PPPoEPassword = input.PPPoEPassword
	}
	profile.DisableWWWService = input.DisableWWWService
	profile.EnableAPIService = input.EnableAPIService
	profile.EnableAPISSLService = input.EnableAPISSLService
}

func sanitizeIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Router"
	}
	replacer := strings.NewReplacer(" ", "-", "\"", "", "'", "")
	return replacer.Replace(value)
}
