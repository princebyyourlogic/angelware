package stun

import (
	"bytes"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

var (
	t0      = time.Unix(1_000_000, 0)
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
	server  = netip.MustParseAddr("192.0.2.10")
)

func at(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func directRouter(port, alt int) *Router {
	cfg := Config{PublicIP: server, Port: port, AltPort: alt, Mode: Direct}
	return NewRouter(cfg, discard, nil, nil)
}

// --- SvR 2007: packed v2 discovery on 3074/3075 ------------------------------

func TestDiscoveryV2(t *testing.T) {
	r := directRouter(3074, 3075)
	client := netip.MustParseAddrPort("192.0.2.7:31001")
	var out []Outbound
	for _, p := range []string{"1e0200" /* captured from the retail game */, "14020000", "14020003", "14020002"} {
		out = append(out, r.Route(unhex(p), client, primary, t0)...)
	}
	if len(out) != 3 {
		t.Fatalf("got %d replies, want change-IP withheld", len(out))
	}
	if got := hex.EncodeToString(out[0].Payload); got != "1f0200c000020719"+"79" {
		t.Errorf("ip reply %s", got)
	}
	if out[1].From.Alt || hex.EncodeToString(out[1].Payload[9:]) != "c000020a020c" {
		t.Errorf("nat test 1 reply %+v", out[1])
	}
	if !out[2].From.Alt {
		t.Error("nat test 3 must come from the second port")
	}
}

// Join request shaped like the retail game's: type 0x0a, version 2, HMAC[10], id,
// initiator 198.51.100.110:3074, target 198.51.100.141:41721.
var intro = unhex("0a0200" + "39b1ed66f5423717b15e" + "b5e50a28" + "c633646e020c" + "c633648df9a2")

var keepalivePacket = append(unhex("0e0200"), make([]byte, 26)...)

func TestIntroductionForwarded(t *testing.T) {
	r := directRouter(3074, 3075)
	host, guest := netip.MustParseAddrPort("198.51.100.141:41721"), netip.MustParseAddrPort("198.51.100.110:3074")
	r.Route(keepalivePacket, host, primary, t0)
	out := r.Route(intro, guest, primary, at(1))
	if len(out) != 1 || out[0].To != host || out[0].Payload[0] != 0x0b || !bytes.Equal(out[0].Payload[1:], intro[1:]) {
		t.Fatalf("got %+v", out)
	}
	if out := r.Route(intro, guest, primary, at(122)); out != nil {
		t.Fatal("forwarded to a target not seen for two minutes")
	}
}

func TestIntroductionRefused(t *testing.T) {
	r := directRouter(3074, 3075)
	var out []Outbound
	out = append(out, r.Route(intro, netip.MustParseAddrPort("198.51.100.110:3074"), primary, t0)...) // host never seen
	r.Route(keepalivePacket, netip.MustParseAddrPort("198.51.100.141:41721"), primary, t0)
	out = append(out, r.Route(intro, netip.MustParseAddrPort("198.51.100.99:3074"), primary, t0)...) // spoofed initiator
	if len(out) != 0 {
		t.Fatalf("forwarded %+v", out)
	}
}

// --- CoD BRO: padded v1 discovery on 2273/2274 (codstun's vectors) -----------

func TestWireVectorsV1(t *testing.T) {
	client := netip.MustParseAddrPort("198.51.100.7:31001")
	if got := hex.EncodeToString(ipReplyPacket(1, client)); got != "1f000100c633640719790000" {
		t.Errorf("ip reply %s", got)
	}
	alt := netip.MustParseAddrPort("192.0.2.11:2273")
	if got := hex.EncodeToString(natReplyPacket(1, client, alt)); got != "15000100c633640719790000c000020be108" {
		t.Errorf("nat reply %s", got)
	}
}

func TestDirectV1SingleAddress(t *testing.T) {
	r := directRouter(2273, 2274)
	client := netip.MustParseAddrPort("198.51.100.7:31001")
	// The game leaves the pad byte uninitialised.
	if out := r.Route(unhex("1eff0100"), client, primary, t0); len(out) != 1 || len(out[0].Payload) != 12 {
		t.Fatalf("ip reply %+v", out)
	}
	for _, flags := range []string{"01", "03"} {
		if out := r.Route(unhex("14000100"+flags+"000000"), client, primary, t0); out != nil {
			t.Errorf("flags %s answered from one address", flags)
		}
	}
	out := r.Route(unhex("1400010002000000"), client, primary, t0)
	if len(out) != 1 || !out[0].From.Alt {
		t.Fatalf("change port %+v", out)
	}
}

func TestMalformed(t *testing.T) {
	for _, p := range []string{"", "1e", "1e00010000", "1e000200", "1400010004000000", "0a0200", "ffffffff"} {
		if _, err := parse(unhex(p)); err == nil {
			t.Errorf("%q parsed", p)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{PublicIP: server, Port: 2273, AltPort: 2274, Mode: Adaptive, RelayLo: 20000, RelayHi: 20199,
		RelayMaxClients: 64, DirectWindow: time.Second}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Config){
		"same ports":     func(c *Config) { c.AltPort = c.Port },
		"no relay range": func(c *Config) { c.RelayLo, c.RelayHi = 0, 0 },
		"range overlaps": func(c *Config) { c.RelayLo = 2270 },
		"window low":     func(c *Config) { c.DirectWindow = 0 },
		"window high":    func(c *Config) { c.DirectWindow = 2100 * time.Millisecond },
		"capacity":       func(c *Config) { c.RelayMaxClients = 1 },
		"bad mode":       func(c *Config) { c.Mode = "fast" },
		"ipv6":           func(c *Config) { c.PublicIP = netip.MustParseAddr("2001:db8::1") },
	} {
		c := ok
		edit(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
