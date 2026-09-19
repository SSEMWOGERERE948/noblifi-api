package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const remoteAccessFirewallComment = "NobliFi remote access"

var managedUFWRulePattern = regexp.MustCompile(`^\[\s*([0-9]+)\]\s+([0-9]+)/tcp\s+.*#\s*NobliFi remote access ([0-9]+)\s*$`)

type remoteAccessFirewall interface {
	Reconcile(ctx context.Context, desiredPorts map[int]struct{}) error
}

type ufwRemoteAccessFirewall struct {
	runner        commandRunner
	sourceCIDR    string
	mu            sync.Mutex
	missingWarned bool
	lastSummary   string
}

type managedUFWRule struct {
	Number int
	Port   int
}

func newUFWRemoteAccessFirewall(runner commandRunner, sourceCIDR string) *ufwRemoteAccessFirewall {
	return &ufwRemoteAccessFirewall{runner: runner, sourceCIDR: strings.TrimSpace(sourceCIDR)}
}

func (f *ufwRemoteAccessFirewall) Reconcile(ctx context.Context, desiredPorts map[int]struct{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := validateRemoteAccessSourceCIDR(f.sourceCIDR); err != nil {
		return err
	}
	for port := range desiredPorts {
		if port < 1024 || port > 65535 {
			return fmt.Errorf("invalid desired remote access port %d", port)
		}
	}

	status, err := f.runner.Run(ctx, "ufw", "status", "numbered")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			if !f.missingWarned {
				log.Printf("remote firewall skipped: ufw executable not found")
				f.missingWarned = true
			}
			return nil
		}
		return fmt.Errorf("check UFW status: %w", err)
	}
	f.missingWarned = false
	if !ufwStatusActive(string(status)) {
		return nil
	}

	rules := parseManagedUFWRules(string(status))
	existing := make(map[int]bool, len(rules))
	stale := make([]managedUFWRule, 0)
	for _, rule := range rules {
		if _, wanted := desiredPorts[rule.Port]; !wanted || existing[rule.Port] {
			stale = append(stale, rule)
			continue
		}
		existing[rule.Port] = true
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].Number > stale[j].Number })
	for _, rule := range stale {
		if _, err := f.runner.Run(ctx, "ufw", "--force", "delete", strconv.Itoa(rule.Number)); err != nil {
			return fmt.Errorf("remove stale TCP port %d rule %d: %w", rule.Port, rule.Number, err)
		}
		log.Printf("remote firewall removed stale port=%d", rule.Port)
	}

	ports := sortedRemoteAccessPorts(desiredPorts)
	changed := len(stale) > 0
	for _, port := range ports {
		if existing[port] {
			continue
		}
		args := ufwAllowArgs(port, f.sourceCIDR)
		if _, err := f.runner.Run(ctx, "ufw", args...); err != nil {
			return fmt.Errorf("allow TCP port %d: %w", port, err)
		}
		changed = true
		log.Printf("remote firewall allowed port=%d protocol=tcp", port)
	}

	summary := fmt.Sprintf("desired_ports=%d", len(desiredPorts))
	if !changed && summary != f.lastSummary {
		log.Printf("remote firewall already reconciled %s", summary)
	}
	f.lastSummary = summary
	return nil
}

func validateRemoteAccessSourceCIDR(sourceCIDR string) error {
	if sourceCIDR == "" {
		return nil
	}
	if _, err := netip.ParsePrefix(sourceCIDR); err != nil {
		return fmt.Errorf("invalid NOBLIFI_REMOTE_ACCESS_SOURCE_CIDR %q: %w", sourceCIDR, err)
	}
	return nil
}

func ufwStatusActive(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "Status: active") {
			return true
		}
	}
	return false
}

func parseManagedUFWRules(status string) []managedUFWRule {
	rules := make([]managedUFWRule, 0)
	for _, line := range strings.Split(status, "\n") {
		matches := managedUFWRulePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) != 4 || matches[2] != matches[3] {
			continue
		}
		number, numberErr := strconv.Atoi(matches[1])
		port, portErr := strconv.Atoi(matches[2])
		if numberErr == nil && portErr == nil && port >= 1024 && port <= 65535 {
			rules = append(rules, managedUFWRule{Number: number, Port: port})
		}
	}
	return rules
}

func ufwAllowArgs(port int, sourceCIDR string) []string {
	comment := fmt.Sprintf("%s %d", remoteAccessFirewallComment, port)
	if sourceCIDR == "" {
		return []string{"allow", fmt.Sprintf("%d/tcp", port), "comment", comment}
	}
	return []string{"allow", "from", sourceCIDR, "to", "any", "port", strconv.Itoa(port), "proto", "tcp", "comment", comment}
}

func sortedRemoteAccessPorts(ports map[int]struct{}) []int {
	values := make([]int, 0, len(ports))
	for port := range ports {
		values = append(values, port)
	}
	sort.Ints(values)
	return values
}
