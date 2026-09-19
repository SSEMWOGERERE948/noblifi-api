package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const activeUFWHeader = `Status: active

     To                         Action      From
     --                         ------      ----
`

type firewallCommand struct {
	name string
	args []string
}

type fakeFirewallRunner struct {
	status    string
	statusErr error
	commands  []firewallCommand
	mutateErr error
}

func (f *fakeFirewallRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, firewallCommand{name: name, args: append([]string(nil), args...)})
	if reflect.DeepEqual(args, []string{"status", "numbered"}) {
		return []byte(f.status), f.statusErr
	}
	return nil, f.mutateErr
}

func (f *fakeFirewallRunner) mutations() []firewallCommand {
	if len(f.commands) <= 1 {
		return nil
	}
	return f.commands[1:]
}

func desiredPorts(ports ...int) map[int]struct{} {
	desired := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		desired[port] = struct{}{}
	}
	return desired
}

func TestUFWFirewallAddsDesiredPublicPorts(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader}
	firewall := newUFWRemoteAccessFirewall(runner, "")

	if err := firewall.Reconcile(context.Background(), desiredPorts(22000, 22001)); err != nil {
		t.Fatal(err)
	}
	want := []firewallCommand{
		{name: "ufw", args: []string{"allow", "22000/tcp", "comment", "NobliFi remote access 22000"}},
		{name: "ufw", args: []string{"allow", "22001/tcp", "comment", "NobliFi remote access 22001"}},
	}
	if got := runner.mutations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutations = %#v, want %#v", got, want)
	}
}

func TestUFWFirewallDoesNotDuplicateExistingRule(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader + "[ 1] 22000/tcp ALLOW IN Anywhere # NobliFi remote access 22000\n"}
	firewall := newUFWRemoteAccessFirewall(runner, "")

	if err := firewall.Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatal(err)
	}
	if got := runner.mutations(); len(got) != 0 {
		t.Fatalf("unexpected mutations: %#v", got)
	}
}

func TestUFWFirewallRemovesOnlyStaleManagedRulesDescending(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader + `
[ 1] 22/tcp ALLOW IN Anywhere
[ 2] 22000/tcp ALLOW IN Anywhere # NobliFi remote access 22000
[ 3] 22001/tcp ALLOW IN Anywhere # NobliFi remote access 22001
[ 4] 22001/tcp ALLOW IN 198.51.100.4 # Administrator temporary access
[ 5] 22002/tcp ALLOW IN Anywhere # NobliFi remote access 22002
`}
	firewall := newUFWRemoteAccessFirewall(runner, "")

	if err := firewall.Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatal(err)
	}
	want := []firewallCommand{
		{name: "ufw", args: []string{"--force", "delete", "5"}},
		{name: "ufw", args: []string{"--force", "delete", "3"}},
	}
	if got := runner.mutations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutations = %#v, want %#v", got, want)
	}
}

func TestUFWFirewallInactiveDoesNotMutate(t *testing.T) {
	runner := &fakeFirewallRunner{status: "Status: inactive\n"}
	if err := newUFWRemoteAccessFirewall(runner, "").Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatal(err)
	}
	if got := runner.mutations(); len(got) != 0 {
		t.Fatalf("unexpected mutations: %#v", got)
	}
}

func TestUFWFirewallMissingDoesNotFail(t *testing.T) {
	runner := &fakeFirewallRunner{statusErr: exec.ErrNotFound}
	if err := newUFWRemoteAccessFirewall(runner, "").Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatalf("missing UFW returned error: %v", err)
	}
}

func TestUFWFirewallUsesConfiguredSourceCIDR(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader}
	firewall := newUFWRemoteAccessFirewall(runner, "203.0.113.10/32")

	if err := firewall.Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatal(err)
	}
	want := []string{"allow", "from", "203.0.113.10/32", "to", "any", "port", "22000", "proto", "tcp", "comment", "NobliFi remote access 22000"}
	if got := runner.mutations(); len(got) != 1 || !reflect.DeepEqual(got[0].args, want) {
		t.Fatalf("allow command = %#v, want %#v", got, want)
	}
}

func TestUFWFirewallRejectsInvalidSourceCIDRBeforeCommand(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader}
	err := newUFWRemoteAccessFirewall(runner, "not-a-cidr").Reconcile(context.Background(), desiredPorts(22000))
	if err == nil || !strings.Contains(err.Error(), "invalid NOBLIFI_REMOTE_ACCESS_SOURCE_CIDR") {
		t.Fatalf("error = %v, want invalid CIDR error", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid CIDR executed commands: %#v", runner.commands)
	}
}

func TestUFWFirewallReturnsPortSpecificAllowError(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader, mutateErr: errors.New("permission denied")}
	err := newUFWRemoteAccessFirewall(runner, "").Reconcile(context.Background(), desiredPorts(22001))
	if err == nil || !strings.Contains(err.Error(), "allow TCP port 22001") {
		t.Fatalf("error = %v, want port-specific allow error", err)
	}
}

func TestParseManagedUFWRulesRequiresExactCommentAndMatchingPort(t *testing.T) {
	status := activeUFWHeader + `
[ 1] 22000/tcp ALLOW IN Anywhere # NobliFi remote access 22000
[ 2] 22001/tcp (v6) ALLOW IN Anywhere (v6) # NobliFi remote access 22001
[ 3] 22002/tcp ALLOW IN Anywhere # NobliFi remote access 22999
[ 4] 22003/tcp ALLOW IN Anywhere # NobliFi remote access backup 22003
[ 5] 22/tcp ALLOW IN Anywhere
`
	got := parseManagedUFWRules(status)
	want := []managedUFWRule{{Number: 1, Port: 22000}, {Number: 2, Port: 22001}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %#v, want %#v", got, want)
	}
}

func TestUFWFirewallRestartRemovesPersistedStaleRule(t *testing.T) {
	runner := &fakeFirewallRunner{status: activeUFWHeader + `
[ 1] 22000/tcp ALLOW IN Anywhere # NobliFi remote access 22000
[ 2] 22001/tcp ALLOW IN Anywhere # NobliFi remote access 22001
`}
	if err := newUFWRemoteAccessFirewall(runner, "").Reconcile(context.Background(), desiredPorts(22000)); err != nil {
		t.Fatal(err)
	}
	want := []firewallCommand{{name: "ufw", args: []string{"--force", "delete", "2"}}}
	if got := runner.mutations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutations = %#v, want %#v", got, want)
	}
}

func TestPublicPortsAreIndependentOfRouterTargetPorts(t *testing.T) {
	for name, publicPort := range map[string]int{"WinBox": 22000, "WebFig": 22001} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeFirewallRunner{status: activeUFWHeader}
			if err := newUFWRemoteAccessFirewall(runner, "").Reconcile(context.Background(), desiredPorts(publicPort)); err != nil {
				t.Fatal(err)
			}
			if got := runner.mutations()[0].args[1]; got != strconv.Itoa(publicPort)+"/tcp" {
				t.Fatalf("allowed port = %q, want public port %d", got, publicPort)
			}
		})
	}
}
