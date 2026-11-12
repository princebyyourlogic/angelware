package main

import "testing"

func TestObserverConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, mode, rewrite string
		valid               bool
	}{
		{"enabled", "adaptive", "on", true},
		{"direct", "direct", "on", false},
		{"missing-rewrite", "adaptive", "off", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ANGELWARE_PUBLIC_IP", "203.0.113.1")
			t.Setenv("ANGELWARE_BRO", "off")
			t.Setenv("ANGELWARE_STUN_MODE", tt.mode)
			t.Setenv("ANGELWARE_SVR_RELAY_REWRITE", tt.rewrite)
			t.Setenv("ANGELWARE_SVR_OBSERVER", "on")
			_, err := loadConfig()
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}
