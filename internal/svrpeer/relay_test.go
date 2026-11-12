package svrpeer

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRetailYarrowVector(t *testing.T) {
	// Independently checked against native LibTomCrypt Yarrow with entropy 0..127.
	h := make([]byte, 161)
	for i := range 128 {
		h[160-i] = byte(i)
	}
	want := unhex("0599c52550016f1c2bcd810460ff6822a6e7b7c966e315f99415cf40")
	if got := privateAt(h, 32); !bytes.Equal(got, want) {
		t.Fatalf("Yarrow scalar %x, want %x", got, want)
	}
}

func TestGeneratorStateRecovery(t *testing.T) {
	s := uint32(123456789)
	first := s
	var word uint32
	for i := range 4 {
		word |= uint32(byte(s)) << (8 * i)
		s = next(s)
	}
	found := false
	for _, candidate := range States(word) {
		if candidate == first {
			found = true
		}
	}
	if !found {
		t.Fatal("public bytes did not recover their known state")
	}
	h := history(first, 160)
	state := first
	const inverse = 1407677000
	for i, got := range h {
		if got != byte(state) {
			t.Fatalf("rewind byte %d", i)
		}
		previous := uint32(uint64(state) * inverse % modulus)
		if next(previous) != state {
			t.Fatal("rewind does not invert forward generator")
		}
		state = previous
	}
}

func TestMalformedSessionPackets(t *testing.T) {
	address := netip.MustParseAddrPort("203.0.113.1:20000")
	for n := range 120 {
		data := bytes.Repeat([]byte{0xff}, n)
		before := bytes.Clone(data)
		if got, count := rewritePacket(data, [8]byte{}, make([]byte, 16), address); count != 0 {
			t.Fatalf("malformed packet of length %d was changed: %x", n, got)
		}
		if !bytes.Equal(before, data) {
			t.Fatal("parser changed input")
		}
	}
}

func TestCapturedRelayRewrite(t *testing.T) {
	t.Run("distinct_public_ips", func(t *testing.T) { capturedRelayRewrite(t, false) })
	t.Run("shared_public_ip", func(t *testing.T) { capturedRelayRewrite(t, true) })
}

// Exercise the complete recovery/handshake/authenticated rewrite path in CI,
// without shipping account data, real room keys, or private packet captures.
func TestSyntheticRelayRewrite(t *testing.T) {
	for _, sharedIP := range []bool{false, true} {
		t.Run(map[bool]string{false: "distinct-public-ips", true: "shared-public-ip"}[sharedIP], func(t *testing.T) {
			state := uint32(123456789)
			private := privateAt(history(state, 160), 32)
			remote := privateAt(history(987654321, 160), 32)
			roomID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			roomKey := bytes.Repeat([]byte{0x42}, 16)
			public := func(scalar []byte) publicKey {
				x, y := elliptic.P224().ScalarBaseMult(scalar)
				return publicKey{x, y}
			}
			traffic := trafficKey(private, public(remote), roomKey)
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			e := New(log, func(id [8]byte) ([]byte, bool) { return bytes.Clone(roomKey), id == roomID })
			host := netip.MustParseAddrPort("198.51.100.1:3074")
			guest := netip.MustParseAddrPort("198.51.100.2:3074")
			if sharedIP {
				guest = netip.MustParseAddrPort("198.51.100.1:3075")
			}
			virtual := netip.MustParseAddrPort("203.0.113.1:20000")
			guestVirtual := netip.MustParseAddrPort("203.0.113.1:20001")
			var seed uint32
			for i := range 4 {
				seed |= uint32(byte(state)) << (8 * i)
				state = next(state)
			}
			now := time.Now()
			e.recordSeed(host.Addr(), seed, now)
			if sharedIP {
				e.recordSeed(host.Addr(), 0xdeadbeef, now) // unrelated login on the same NAT
			}
			handshake := func(kind byte, scalar []byte, n int) []byte {
				p := public(scalar)
				blob, err := asn1.Marshal(struct {
					Flags asn1.BitString
					Size  int
					X, Y  *big.Int
				}{asn1.BitString{Bytes: []byte{0}, BitLength: 1}, 28, p.x, p.y})
				if err != nil || len(blob) > 100 {
					t.Fatalf("encode public key: %v", err)
				}
				packet := make([]byte, n)
				packet[0], packet[1] = kind, 2
				copy(packet[n-100:], blob)
				if kind == 3 {
					copy(packet[61:69], roomID[:])
				}
				return packet
			}
			e.Rewrite(2, 1, guest, guestVirtual, host, virtual, handshake(3, remote, 169), now)
			e.Rewrite(1, 2, host, virtual, guest, guestVirtual, handshake(4, private, 106), now)
			if !bytes.Equal(e.pairs[pair{1, 2}].key, traffic) {
				t.Fatal("handshake did not recover the expected traffic key")
			}
			join := func(endpoint netip.AddrPort) []byte {
				addr := make([]byte, 25)
				ip := endpoint.Addr().As4()
				copy(addr, ip[:])
				binary.LittleEndian.PutUint16(addr[4:], endpoint.Port())
				copy(addr[18:24], addr[:6])
				w := bitbuf.NewWriter(false)
				for range 2 { // generic host record, then room-bound title record
					w.Raw([]byte("synthetic-host\x00")).Raw(make([]byte, 8)).U32(25).Raw(addr)
				}
				return w.U32(8).Raw(roomID[:]).U32(16).Raw(roomKey).Bytes()
			}
			seal := func(payload []byte) []byte {
				plain := make([]byte, 12+len(payload))
				plain[5], plain[9] = 2, 0x4f // compact DATA chunk, no clear tail
				binary.LittleEndian.PutUint16(plain[7:], uint16(len(payload)))
				copy(plain[12:], payload)
				padded := make([]byte, (len(plain)+7)&^7)
				copy(padded, plain)
				ciphertext, err := dwcrypto.Encrypt(traffic, dwcrypto.SeedIV(1), padded)
				if err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, 16+len(ciphertext))
				packet[0], packet[1], packet[4] = 6, 2, 1
				binary.LittleEndian.PutUint16(packet[14:], uint16(len(plain)))
				copy(packet[16:], ciphertext)
				mac := hmac.New(sha1.New, traffic)
				mac.Write(packet[:6])
				mac.Write(packet[16:])
				copy(packet[6:14], mac.Sum(nil)[:8])
				return packet
			}
			packet, want := seal(join(host)), seal(join(virtual))
			before := bytes.Clone(packet)
			got := e.Rewrite(1, 2, host, virtual, guest, guestVirtual, packet, now)
			if !bytes.Equal(got, want) || bytes.Equal(got, packet) {
				t.Fatal("authenticated join-accept did not select the relay in both host records")
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("input packet mutated")
			}
			packet[16] ^= 1
			if got := e.Rewrite(1, 2, host, virtual, guest, guestVirtual, packet, now); !bytes.Equal(got, packet) {
				t.Fatal("unauthenticated packet rewritten")
			}
		})
	}
}

func capturedRelayRewrite(t *testing.T, sharedIP bool) {
	path := os.Getenv("ANGELWARE_TEST_SVR_PEER_FIXTURE")
	if path == "" {
		t.Skip("set ANGELWARE_TEST_SVR_PEER_FIXTURE to an ignored local capture fixture")
	}
	var fixture struct {
		Auth []struct {
			IP   string `json:"ip"`
			Seed uint32 `json:"seed"`
		} `json:"auth"`
		RoomID     string                            `json:"room_id"`
		RoomKey    string                            `json:"room_key"`
		TrafficKey string                            `json:"traffic_key"`
		Packets    []struct{ From, To, Data string } `json:"packets"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	id, key := [8]byte(unhex(fixture.RoomID)), unhex(fixture.RoomKey)
	traffic := unhex(fixture.TrafficKey)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := New(log, func(want [8]byte) ([]byte, bool) { return bytes.Clone(key), want == id })
	now := time.Now()
	for _, auth := range fixture.Auth {
		ip := netip.MustParseAddr(auth.IP)
		if sharedIP {
			ip = netip.MustParseAddr("198.51.100.10")
		}
		e.recordSeed(ip, auth.Seed, now)
	}
	virtual := map[int]netip.AddrPort{
		1: netip.MustParseAddrPort("203.0.113.1:20000"),
		2: netip.MustParseAddrPort("203.0.113.1:20001"),
	}
	idFor := func(a netip.AddrPort) int {
		if a.Addr() == netip.MustParseAddr("192.168.2.141") {
			return 1
		}
		return 2
	}
	changed := 0
	for _, frame := range fixture.Packets {
		from, to := netip.MustParseAddrPort(frame.From), netip.MustParseAddrPort(frame.To)
		sender, destination := idFor(from), idFor(to)
		if sharedIP {
			ip := netip.MustParseAddr("198.51.100.10")
			from, to = netip.AddrPortFrom(ip, uint16(40000+sender)), netip.AddrPortFrom(ip, uint16(40000+destination))
		}
		packet := unhex(frame.Data)
		original := bytes.Clone(packet)
		out := e.Rewrite(sender, destination, from, virtual[sender], to, virtual[destination], packet, now)
		if !bytes.Equal(original, packet) {
			t.Fatal("rewriter mutated shared receive buffer")
		}
		if bytes.Equal(out, packet) {
			continue
		}
		changed++
		if len(out) != len(packet) {
			t.Fatal("packet length changed")
		}
		mac := hmac.New(sha1.New, traffic)
		mac.Write(out[:6])
		mac.Write(out[16:])
		if !hmac.Equal(mac.Sum(nil)[:8], out[6:14]) {
			t.Fatal("rewritten HMAC rejected")
		}
		n := int(binary.LittleEndian.Uint16(out[14:]))
		padded := (n + 7) &^ 7
		seq := uint32(binary.LittleEndian.Uint16(out[4:]))
		plain, err := dwcrypto.Decrypt(traffic, dwcrypto.SeedIV(seq), out[16:16+padded])
		if err != nil {
			t.Fatal(err)
		}
		// The independent capture decoder located two host blobs in DATA 0x4f.
		for _, bit := range []int{145, 1177} {
			probe := bits{data: plain[12:n], pos: bit, ok: true}
			address := probe.raw(25)
			want := []byte{203, 0, 113, 1, 0x20, 0x4e}
			if !probe.ok || !bytes.Equal(address[:6], want) || !bytes.Equal(address[18:24], want) {
				t.Fatalf("host address at bit %d did not select relay", bit)
			}
		}
		bad := bytes.Clone(packet)
		bad[16] ^= 1
		if got := e.Rewrite(sender, destination, from, virtual[sender], to, virtual[destination], bad, now); !bytes.Equal(got, bad) {
			t.Fatal("tampered packet was rewritten")
		}
	}
	if changed != 1 {
		t.Fatalf("rewrote %d captured packets, want 1", changed)
	}
	if !bytes.Equal(e.pairs[pair{1, 2}].key, traffic) {
		t.Fatal("server derived wrong traffic key")
	}
	// Ordinary match datagrams must stay opaque and keep the association alive.
	game := []byte{1, 0x31, 0, 0x0a, 0, 2}
	later := now.Add(2 * time.Minute)
	if got := e.Rewrite(1, 2, netip.AddrPort{}, virtual[1], netip.AddrPort{}, virtual[2], game, later); !bytes.Equal(got, game) {
		t.Fatal("ordinary match traffic changed")
	}
	if e.pairs[pair{1, 2}].lastSeen != later {
		t.Fatal("match traffic did not refresh pair")
	}
}
