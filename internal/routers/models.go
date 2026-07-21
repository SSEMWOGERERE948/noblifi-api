package routers

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Router struct {
	ID                    uuid.UUID              `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	SiteID                *uuid.UUID             `gorm:"type:uuid" json:"site_id"`
	Name                  string                 `json:"name"`
	SiteName              *string                `json:"site_name"`
	ExpectedModel         *string                `json:"expected_model"`
	Model                 *string                `json:"model"`
	SerialNumber          *string                `gorm:"uniqueIndex" json:"serial_number"`
	MacAddress            *string                `json:"mac_address"`
	RouterOSVersion       *string                `json:"routeros_version"`
	ManagementIP          *string                `json:"management_ip"`
	APIUsername           *string                `json:"api_username"`
	APIPasswordEncrypted  *string                `json:"api_password_encrypted"`
	RadiusSecretEncrypted *string                `json:"radius_secret_encrypted"`
	WireGuardTunnelIP     *string                `gorm:"uniqueIndex" json:"wireguard_tunnel_ip"`
	WireGuardPublicKey    *string                `gorm:"uniqueIndex" json:"wireguard_public_key"`
	WireGuardStatus       string                 `gorm:"default:disabled" json:"wireguard_status"`
	WireGuardLastSeenAt   *time.Time             `json:"wireguard_last_seen_at"`
	Status                string                 `gorm:"default:pending" json:"status"`
	ClaimToken            string                 `gorm:"uniqueIndex" json:"claim_token"`
	ClaimTokenExpiresAt   *time.Time             `json:"claim_token_expires_at"`
	LastSeenAt            *time.Time             `json:"last_seen_at"`
	ProvisionedAt         *time.Time             `json:"provisioned_at"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	Interfaces            []RouterInterface      `gorm:"foreignKey:RouterID" json:"interfaces,omitempty"`
	PortAssignments       []RouterPortAssignment `gorm:"foreignKey:RouterID" json:"port_assignments,omitempty"`
	SetupSession          *RouterSetupSession    `gorm:"foreignKey:RouterID" json:"setup_session,omitempty"`
	NetworkProfile        *RouterNetworkProfile  `gorm:"foreignKey:RouterID" json:"network_profile,omitempty"`
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
