package portprofiles

import (
	"errors"
	"fmt"
	"strings"
)

var allowedRoles = map[string]bool{
	"WAN":         true,
	"HOTSPOT_LAN": true,
	"STAFF_LAN":   true,
	"POS_LAN":     true,
	"CCTV_LAN":    true,
	"DISABLED":    true,
}

type Assignment struct {
	Interface     string `json:"interface"`
	InterfaceName string `json:"interface_name"`
	Role          string `json:"role"`
}

func (a Assignment) Name() string {
	if strings.TrimSpace(a.InterfaceName) != "" {
		return strings.TrimSpace(a.InterfaceName)
	}
	return strings.TrimSpace(a.Interface)
}

func Validate(assignments []Assignment) error {
	seen := map[string]bool{}
	wanCount := 0
	hotspotCount := 0
	staffCount := 0

	for _, assignment := range assignments {
		name := assignment.Name()
		role := strings.TrimSpace(assignment.Role)
		if name == "" {
			return errors.New("interface name is required")
		}
		if role == "" {
			return fmt.Errorf("role is required for interface %s", name)
		}
		if !allowedRoles[role] {
			return fmt.Errorf("unknown role: %s", role)
		}
		if seen[name] {
			return fmt.Errorf("interface %s has more than one role", name)
		}
		seen[name] = true
		if role == "WAN" {
			wanCount++
		}
		if role == "HOTSPOT_LAN" {
			hotspotCount++
		}
		if role == "STAFF_LAN" {
			staffCount++
		}
	}

	if wanCount != 1 {
		return errors.New("exactly one WAN interface is required")
	}
	if hotspotCount < 1 {
		return errors.New("at least one HOTSPOT_LAN interface is required")
	}
	if len(assignments) >= 3 && staffCount < 1 {
		return errors.New("reserve at least one STAFF_LAN interface for management access")
	}
	return nil
}
