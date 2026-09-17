package main

import "testing"

func TestValidateWinboxTarget(t *testing.T) {
	for _, target := range []string{"10.77.0.2:8291", "192.168.88.1:8291"} {
		if err := validateWinboxTarget(target); err != nil {
			t.Fatalf("expected %s to be accepted: %v", target, err)
		}
	}
	for _, target := range []string{"8.8.8.8:8291", "10.77.0.2:22", "invalid"} {
		if err := validateWinboxTarget(target); err == nil {
			t.Fatalf("expected %s to be rejected", target)
		}
	}
}
