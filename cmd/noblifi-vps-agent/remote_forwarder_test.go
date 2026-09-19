package main

import "testing"

func TestValidateRemoteAccessTarget(t *testing.T) {
	for _, target := range []string{"10.77.0.2:80", "10.77.0.2:8291", "192.168.88.1:80"} {
		if err := validateRemoteAccessTarget(target); err != nil {
			t.Fatalf("expected %s to be accepted: %v", target, err)
		}
	}
	for _, target := range []string{"8.8.8.8:80", "8.8.8.8:8291", "10.77.0.2:22", "invalid"} {
		if err := validateRemoteAccessTarget(target); err == nil {
			t.Fatalf("expected %s to be rejected", target)
		}
	}
}
