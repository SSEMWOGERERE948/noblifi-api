package portprofiles

import (
	"errors"
	"fmt"
	"strings"
)

const (
	RoleWAN        = "WAN"
	RoleHotspotLAN = "HOTSPOT_LAN"
	RoleFreeLAN    = "FREE_LAN"
	RoleDisabled   = "DISABLED"
)

var allowedRoles = map[string]bool{
	RoleWAN:        true,
	RoleHotspotLAN: true,
	RoleFreeLAN:    true,
	RoleDisabled:   true,
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
	if len(assignments) == 0 {
		return errors.New("at least one interface assignment is required")
	}

	seen := make(map[string]bool)

	wanCount := 0
	hotspotCount := 0
	freeCount := 0

	for _, assignment := range assignments {
		name := strings.TrimSpace(assignment.Name())
		role := strings.ToUpper(
			strings.TrimSpace(assignment.Role),
		)

		if name == "" {
			return errors.New("interface name is required")
		}

		if role == "" {
			return fmt.Errorf(
				"role is required for interface %s",
				name,
			)
		}

		if !allowedRoles[role] {
			return fmt.Errorf(
				"unsupported role %q for interface %s",
				role,
				name,
			)
		}

		if seen[name] {
			return fmt.Errorf(
				"interface %s has more than one role",
				name,
			)
		}

		seen[name] = true

		switch role {
		case RoleWAN:
			wanCount++

		case RoleHotspotLAN:
			hotspotCount++

		case RoleFreeLAN:
			freeCount++

		case RoleDisabled:
			// Nothing else required.
		}
	}

	// NobliFi requires exactly one upstream internet/WAN port.
	if wanCount != 1 {
		return errors.New(
			"exactly one WAN interface is required",
		)
	}

	// At least one physical port must provide hotspot access.
	if hotspotCount < 1 {
		return errors.New(
			"select at least one port for the NobliFi hotspot",
		)
	}

	// IMPORTANT:
	// Always leave at least one physical LAN port outside the captive portal.
	//
	// This gives the installer/local administrator a direct port that is not
	// captured by br-hotspot.
	if freeCount < 1 {
		return errors.New(
			"leave at least one LAN port free and outside the hotspot",
		)
	}

	return nil
}
