package main

import "testing"

func TestTelemetryReportFromRouterOSRows(t *testing.T) {
	report := telemetryReportFromRows(
		[]map[string]string{{
			"=uptime":       "1d2h3m4s",
			"=version":      "7.15.3",
			"=cpu-load":     "18",
			"=free-memory":  "123456",
			"=total-memory": "456789",
			"=board-name":   "RB5009UG+S+",
		}},
		[]map[string]string{{"=name": "shop-router"}},
		[]map[string]string{{
			"=name":        "ether1",
			"=type":        "ether",
			"=mac-address": "AA:BB:CC:DD:EE:FF",
			"=running":     "true",
			"=disabled":    "false",
		}},
		[]map[string]string{
			{"=.id": "*1", "=user": "voucher-1"},
			{"=.id": "*2", "=user": "voucher-2"},
		},
	)

	if report.Identity != "shop-router" {
		t.Fatalf("Identity = %q, want shop-router", report.Identity)
	}
	if report.Model != "RB5009UG+S+" {
		t.Fatalf("Model = %q, want RB5009UG+S+", report.Model)
	}
	if report.RouterOSVersion != "7.15.3" {
		t.Fatalf("RouterOSVersion = %q, want 7.15.3", report.RouterOSVersion)
	}
	if report.Uptime != "1d2h3m4s" {
		t.Fatalf("Uptime = %q, want 1d2h3m4s", report.Uptime)
	}
	if report.UptimeSeconds == nil || *report.UptimeSeconds != 93784 {
		t.Fatalf("UptimeSeconds = %v, want 93784", report.UptimeSeconds)
	}
	if report.CPULoad != "18" {
		t.Fatalf("CPULoad = %q, want 18", report.CPULoad)
	}
	if report.ActiveHotspotUsers == nil || *report.ActiveHotspotUsers != 2 {
		t.Fatalf("ActiveHotspotUsers = %v, want 2", report.ActiveHotspotUsers)
	}
	if len(report.Interfaces) != 1 {
		t.Fatalf("Interfaces length = %d, want 1", len(report.Interfaces))
	}
	if !report.Interfaces[0].Running || report.Interfaces[0].Disabled {
		t.Fatalf("interface flags = running:%t disabled:%t, want running:true disabled:false", report.Interfaces[0].Running, report.Interfaces[0].Disabled)
	}
}

func TestParseRouterOSDurationSeconds(t *testing.T) {
	got := parseRouterOSDurationSeconds("1w2d3h4m5s")
	if got == nil || *got != 788645 {
		t.Fatalf("parseRouterOSDurationSeconds() = %v, want 788645", got)
	}
}

func TestTelemetryReportReadsUnprefixedRouterOSKeys(t *testing.T) {
	report := telemetryReportFromRows(
		[]map[string]string{{"board-name": "hAP ax2", "version": "7.16", "cpu-load": "7"}},
		[]map[string]string{{"name": "tenant-router"}},
		nil,
		nil,
	)

	if report.Identity != "tenant-router" {
		t.Fatalf("Identity = %q, want tenant-router", report.Identity)
	}
	if report.Model != "hAP ax2" {
		t.Fatalf("Model = %q, want hAP ax2", report.Model)
	}
	if report.ActiveHotspotUsers == nil || *report.ActiveHotspotUsers != 0 {
		t.Fatalf("ActiveHotspotUsers = %v, want 0", report.ActiveHotspotUsers)
	}
}
