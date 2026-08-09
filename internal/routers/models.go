package routers

import (
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"gorm.io/datatypes"
)

type Router struct {
	ID                       uuid.UUID              `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	OwnerUserID              *uuid.UUID             `gorm:"type:uuid;index" json:"owner_user_id"`
	SiteID                   *uuid.UUID             `gorm:"type:uuid" json:"site_id"`
	Name                     string                 `json:"name"`
	SiteName                 *string                `json:"site_name"`
	ExpectedModel            *string                `json:"expected_model"`
	Model                    *string                `json:"model"`
	SerialNumber             *string                `gorm:"uniqueIndex" json:"serial_number"`
	MacAddress               *string                `json:"mac_address"`
	RouterOSVersion          *string                `json:"routeros_version"`
	Uptime                   *string                `json:"uptime"`
	CPULoad                  *string                `json:"cpu_load"`
	FreeMemory               *string                `json:"free_memory"`
	TotalMemory              *string                `json:"total_memory"`
	ActiveHotspotUsers       int                    `json:"active_hotspot_users"`
	TelemetryUpdatedAt       *time.Time             `json:"telemetry_updated_at"`
	TelemetryLastError       *string                `json:"telemetry_last_error"`
	ManagementIP             *string                `json:"management_ip"`
	APIUsername              *string                `json:"api_username"`
	APIPasswordEncrypted     *string                `json:"api_password_encrypted"`
	RadiusSecretEncrypted    *string                `json:"radius_secret_encrypted"`
	WireGuardTunnelIP        *string                `gorm:"unique" json:"wireguard_tunnel_ip"`
	WireGuardPublicKey       *string                `gorm:"unique" json:"wireguard_public_key"`
	WireGuardStatus          string                 `gorm:"default:disabled" json:"wireguard_status"`
	WireGuardLastSeenAt      *time.Time             `json:"wireguard_last_seen_at"`
	WireGuardPeerStatus      string                 `gorm:"default:waiting_for_router_key;index" json:"wireguard_peer_status"`
	WireGuardPeerUpdatedAt   *time.Time             `json:"wireguard_peer_updated_at"`
	WireGuardLastHandshakeAt *time.Time             `json:"wireguard_last_handshake_at"`
	WireGuardLastError       *string                `json:"wireguard_last_error"`
	RemoteWebPort            *int                   `gorm:"uniqueIndex" json:"remote_web_port"`
	RemoteWinboxPort         *int                   `gorm:"uniqueIndex" json:"remote_winbox_port"`
	RemoteAccessStatus       string                 `gorm:"default:disabled;index" json:"remote_access_status"`
	ProvisioningStatus       string                 `gorm:"default:pending;index" json:"provisioning_status"`
	ProvisioningError        *string                `json:"provisioning_error"`
	DeleteRequestedAt        *time.Time             `json:"delete_requested_at"`
	DeletedAt                *time.Time             `gorm:"index" json:"deleted_at"`
	Status                   string                 `gorm:"default:pending" json:"status"`
	ClaimToken               string                 `gorm:"uniqueIndex" json:"claim_token"`
	ClaimTokenExpiresAt      *time.Time             `json:"claim_token_expires_at"`
	LastSeenAt               *time.Time             `json:"last_seen_at"`
	ProvisionedAt            *time.Time             `json:"provisioned_at"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
	Interfaces               []RouterInterface      `gorm:"foreignKey:RouterID" json:"interfaces,omitempty"`
	PortAssignments          []RouterPortAssignment `gorm:"foreignKey:RouterID" json:"port_assignments,omitempty"`
	SetupSession             *RouterSetupSession    `gorm:"foreignKey:RouterID" json:"setup_session,omitempty"`
	NetworkProfile           *RouterNetworkProfile  `gorm:"foreignKey:RouterID" json:"network_profile,omitempty"`
}

type RouterSetupSession struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID            uuid.UUID `gorm:"type:uuid;uniqueIndex" json:"router_id"`
	CurrentStep         string    `gorm:"default:remote_access" json:"current_step"`
	RemoteAccessMethod  *string   `json:"remote_access_method"`
	ConfigurationMethod *string   `json:"configuration_method"`
	DeploymentStatus    string    `gorm:"default:draft" json:"deployment_status"`
	ErrorMessage        *string   `json:"error_message"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type RouterNetworkProfile struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID            uuid.UUID `gorm:"type:uuid;uniqueIndex" json:"router_id"`
	Name                string    `json:"name"`
	RadiusServer        string    `json:"radius_server"`
	RadiusSecret        string    `json:"radius_secret"`
	RouterIdentity      string    `json:"router_identity"`
	APIUsername         string    `json:"api_username"`
	APIPassword         string    `json:"api_password"`
	HotspotBridge       string    `json:"hotspot_bridge"`
	StaffBridge         string    `json:"staff_bridge"`
	POSBridge           string    `json:"pos_bridge"`
	CCTVBridge          string    `json:"cctv_bridge"`
	HotspotSubnet       string    `json:"hotspot_subnet"`
	HotspotGateway      string    `json:"hotspot_gateway"`
	HotspotPool         string    `json:"hotspot_pool"`
	StaffSubnet         string    `json:"staff_subnet"`
	StaffGateway        string    `json:"staff_gateway"`
	StaffPool           string    `json:"staff_pool"`
	POSSubnet           string    `json:"pos_subnet"`
	POSGateway          string    `json:"pos_gateway"`
	POSPool             string    `json:"pos_pool"`
	CCTVSubnet          string    `json:"cctv_subnet"`
	CCTVGateway         string    `json:"cctv_gateway"`
	CCTVPool            string    `json:"cctv_pool"`
	HotspotDNSName      string    `json:"hotspot_dns_name"`
	HotspotPortalName   string    `json:"hotspot_portal_name"`
	HotspotTemplateKey  string    `gorm:"default:clean" json:"hotspot_template_key"`
	WANMode             string    `gorm:"default:dhcp" json:"wan_mode"`
	PPPoEUsername       *string   `json:"pppoe_username"`
	PPPoEPassword       *string   `json:"pppoe_password"`
	DisableWWWService   bool      `gorm:"default:true" json:"disable_www_service"`
	EnableAPIService    bool      `gorm:"default:true" json:"enable_api_service"`
	EnableAPISSLService bool      `gorm:"default:true" json:"enable_api_ssl_service"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type RouterInterface struct {
	ID           uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID     uuid.UUID `gorm:"type:uuid;index" json:"router_id"`
	Name         string    `json:"name"`
	Type         *string   `json:"type"`
	MacAddress   *string   `json:"mac_address"`
	Running      bool      `gorm:"default:false" json:"running"`
	Disabled     bool      `gorm:"default:false" json:"disabled"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

type RouterTelemetry struct {
	RouterID           uuid.UUID         `json:"router_id"`
	Name               string            `json:"name"`
	Identity           string            `json:"identity"`
	Model              string            `json:"model"`
	RouterOSVersion    string            `json:"routeros_version"`
	Uptime             string            `json:"uptime"`
	CPULoad            string            `json:"cpu_load"`
	FreeMemory         string            `json:"free_memory"`
	TotalMemory        string            `json:"total_memory"`
	FreeHDD            string            `json:"free_hdd"`
	TotalHDD           string            `json:"total_hdd"`
	Architecture       string            `json:"architecture"`
	BoardName          string            `json:"board_name"`
	ActiveHotspotUsers int               `json:"active_hotspot_users"`
	Interfaces         []RouterInterface `json:"interfaces"`
	LastSeenAt         *time.Time        `json:"last_seen_at"`
}

type CreateRouterInput struct {
	Name          string `json:"name"`
	SiteName      string `json:"site_name"`
	Model         string `json:"model"`
	ExpectedModel string `json:"expected_model"`
}

type AuthUser struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	PortalName    string    `json:"portal_name"`
	Role          string    `json:"role"`
	AccountStatus string    `json:"account_status"`
	RouterLimit   int       `json:"router_limit"`
}

type RemoteAccessInput struct {
	RemoteAccessMethod string `json:"remote_access_method"`
	Host               string `json:"host"`
	APIPort            int    `json:"api_port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
}

type MethodInput struct {
	ConfigurationMethod string `json:"configuration_method"`
}

type RemoteAccessDetails struct {
	RouterID        uuid.UUID `json:"router_id"`
	Address         string    `json:"address"`
	APIAddress      string    `json:"api_address"`
	WinboxAddress   string    `json:"winbox_address"`
	WebURL          string    `json:"web_url"`
	SecureWebURL    string    `json:"secure_web_url"`
	Method          string    `json:"method"`
	WireGuardStatus string    `json:"wireguard_status"`
	Ready           bool      `json:"ready"`
}

type ConnectionTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ConfigPreview struct {
	Summary portprofiles.Summary `json:"summary"`
	Script  string               `json:"script"`
}

type RouterPortAssignment struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID      uuid.UUID `gorm:"type:uuid;index" json:"router_id"`
	InterfaceName string    `json:"interface_name"`
	Role          string    `json:"role"`
	BridgeName    *string   `json:"bridge_name"`
	VLANID        *int      `json:"vlan_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type RouterConfigLog struct {
	ID              uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	RouterID        uuid.UUID      `gorm:"type:uuid;index" json:"router_id"`
	Action          string         `json:"action"`
	Status          string         `json:"status"`
	RequestPayload  datatypes.JSON `json:"request_payload"`
	ResponsePayload datatypes.JSON `json:"response_payload"`
	ErrorMessage    *string        `json:"error_message"`
	CreatedAt       time.Time      `json:"created_at"`
}
