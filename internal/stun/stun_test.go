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

type sent struct {
	secondary bool
	data      []byte
	to        netip.AddrPort
}

func newServer() (*Server, *[]sent, func(bool, []byte, netip.AddrPort)) {
	s := &Server{PublicIP: netip.MustParseAddr("198.51.100.1"), Port: 3074, AltPort: 3075,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), seen: map[netip.AddrPort]time.Time{}}
	var out []sent
	return s, &out, func(sec bool, b []byte, to netip.AddrPort) {
		out = append(out, sent{sec, bytes.Clone(b), to})
	}
}

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func TestDiscoveryV2(t *testing.T) {
	s, out, send := newServer()
	client := netip.MustParseAddrPort("192.0.2.7:31001")
	s.Handle(unhex("1e0200"), client, send) // captured from the retail game
	s.Handle(unhex("14020000"), client, send)
	s.Handle(unhex("14020003"), client, send) // change IP: withheld
	s.Handle(unhex("14020002"), client, send) // change port: from the secondary
	if len(*out) != 3 {
		t.Fatalf("got %d replies", len(*out))
	}
	if got := hex.EncodeToString((*out)[0].data); got != "1f0200c000020719"+"79" {
		t.Errorf("ip reply %s", got)
	}
	nat := (*out)[1]
	if nat.secondary || len(nat.data) != 15 || hex.EncodeToString(nat.data[9:]) != "c6336401020c" {
		t.Errorf("nat test 1 reply %+v", nat)
	}
	if !(*out)[2].secondary {
		t.Error("nat test 3 must come from the secondary port")
	}
}

func TestDiscoveryV1Padded(t *testing.T) {
	s, out, send := newServer()
	s.Handle(unhex("1e000100"), netip.MustParseAddrPort("192.0.2.7:1"), send)
	if len((*out)[0].data) != 12 {
		t.Fatalf("v1 ip reply %x", (*out)[0].data)
	}
}

// Join request shaped like the retail game's: type 0x0a, version 2, HMAC[10], id,
// initiator 198.51.100.110:3074, target 198.51.100.141:41721.
var intro = unhex("0a0200" + "39b1ed66f5423717b15e" + "b5e50a28" + "c633646e020c" + "c633648df9a2")

func TestIntroductionForwarded(t *testing.T) {
	s, out, send := newServer()
	host, guest := netip.MustParseAddrPort("198.51.100.141:41721"), netip.MustParseAddrPort("198.51.100.110:3074")
	s.Handle(append(unhex("0e02"), make([]byte, 27)...), host, send)
	s.Handle(intro, guest, send)
	if len(*out) != 1 || (*out)[0].to != host || (*out)[0].data[0] != 0x0b ||
		!bytes.Equal((*out)[0].data[1:], intro[1:]) {
		t.Fatalf("got %+v", *out)
	}
}

func TestIntroductionRefused(t *testing.T) {
	s, out, send := newServer()
	s.Handle(intro, netip.MustParseAddrPort("198.51.100.110:3074"), send) // host never seen
	s.Handle(append(unhex("0e02"), make([]byte, 27)...), netip.MustParseAddrPort("198.51.100.141:41721"), send)
	s.Handle(intro, netip.MustParseAddrPort("198.51.100.99:3074"), send) // spoofed initiator
	if len(*out) != 0 {
		t.Fatalf("forwarded %+v", *out)
	}
}
