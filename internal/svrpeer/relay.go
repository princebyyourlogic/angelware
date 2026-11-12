package svrpeer

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
)

const (
	seedTTL      = 30 * time.Minute
	pairTTL      = 3 * time.Minute
	maxSeedIPs   = 1024
	maxSeeds     = 8
	maxPairs     = 4096
	maxKeyTrials = 8192
	maxRewind    = 4096
)

type observation struct {
	word       uint32
	at         time.Time
	states     []uint32
	calculated bool
}

type pair struct{ a, b int }

type association struct {
	lastSeen  time.Time
	pubs      map[int]publicKey
	ips       map[int]netip.Addr
	roomID    [8]byte
	room      []byte
	key       []byte
	tried     bool
	initTag   uint16
	sequence  map[int]uint32
	rewritten int
}

// Engine.ObserveLogin is safe for auth goroutines. Rewrite must be serialized by
// the title's UDP router. It never edits direct traffic or logs key material.
type Engine struct {
	Log     *slog.Logger
	RoomKey func([8]byte) ([]byte, bool)

	mu    sync.Mutex
	seeds map[netip.Addr][]*observation
	pairs map[pair]*association
	known map[string][]byte
}

func New(log *slog.Logger, roomKey func([8]byte) ([]byte, bool)) *Engine {
	return &Engine{Log: log, RoomKey: roomKey, seeds: map[netip.Addr][]*observation{},
		pairs: map[pair]*association{}, known: map[string][]byte{}}
}

func (e *Engine) ObserveLogin(peer net.Addr, seed uint32) {
	addr, err := netip.ParseAddrPort(peer.String())
	if err != nil {
		return
	}
	e.recordSeed(addr.Addr().Unmap(), seed, time.Now())
}

func (e *Engine) recordSeed(ip netip.Addr, seed uint32, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.seeds) >= maxSeedIPs {
		for ip, entries := range e.seeds {
			if len(entries) == 0 || now.Sub(entries[len(entries)-1].at) > seedTTL {
				delete(e.seeds, ip)
			}
		}
		if _, ok := e.seeds[ip]; !ok && len(e.seeds) >= maxSeedIPs {
			return
		}
	}
	entries := e.seeds[ip]
	entries = append(entries, &observation{word: seed, at: now})
	if len(entries) > maxSeeds {
		entries = entries[len(entries)-maxSeeds:]
	}
	e.seeds[ip] = entries
}

func (e *Engine) observations(ip netip.Addr, now time.Time) []*observation {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*observation
	entries := e.seeds[ip]
	for i := len(entries) - 1; i >= 0; i-- {
		if now.Sub(entries[i].at) <= seedTTL {
			out = append(out, entries[i])
		}
	}
	return out
}

func publicID(p publicKey) string {
	return string(elliptic.Marshal(elliptic.P224(), p.x, p.y))
}

func (e *Engine) resolve(s *association, first, second int, now time.Time) {
	if s.tried || s.key != nil || len(s.pubs) != 2 || e.RoomKey == nil {
		return
	}
	room, ok := e.RoomKey(s.roomID)
	if !ok || len(room) != 16 {
		return
	}
	s.tried = true
	s.room = room
	ids := []int{first, second}
	for i, id := range ids {
		if private := e.known[publicID(s.pubs[id])]; private != nil {
			s.key = trafficKey(private, s.pubs[ids[1-i]], room)
			return
		}
	}
	start := time.Now()
	trials := 0
	// Try the observed 32-byte gap for every recent login first. The public-key
	// comparison decides correctness, including when many players share one IP.
	for phase := 0; phase < 2; phase++ {
		for i, id := range ids {
			for _, obs := range e.observations(s.ips[id], now) {
				if !obs.calculated {
					obs.states, obs.calculated = States(obs.word), true
				}
				for _, state := range obs.states {
					h := history(state, maxRewind+128)
					lo, hi := 32, 32
					if phase == 1 {
						lo, hi = 0, maxRewind
					}
					for gap := lo; gap <= hi; gap++ {
						if phase == 1 && gap == 32 {
							continue
						}
						trials++
						if trials > maxKeyTrials || time.Since(start) > 2*time.Second {
							e.Log.Warn("peer key recovery budget exceeded", "trials", trials)
							return
						}
						private := privateAt(h, gap)
						if !s.pubs[id].matches(private) {
							continue
						}
						if len(e.known) >= maxSeedIPs {
							clear(e.known)
						}
						e.known[publicID(s.pubs[id])] = bytes.Clone(private)
						s.key = trafficKey(private, s.pubs[ids[1-i]], room)
						e.Log.Info("peer relay key established", "room", s.roomID,
							"rng_gap", gap, "trials", trials, "elapsed", time.Since(start).String())
						return
					}
				}
			}
		}
	}
	e.Log.Warn("peer relay key not recovered", "room", s.roomID, "trials", trials)
}

// Rewrite is called only for a packet already admitted to a relay pair. Control
// endpoints identify possible auth seeds; virtual endpoints are the addresses
// that the match must use. Unknown traffic always passes through unchanged.
func (e *Engine) Rewrite(sender, destination int, senderControl, senderVirtual,
	destinationControl, destinationVirtual netip.AddrPort, packet []byte, now time.Time) []byte {
	if len(packet) < 2 || sender == destination {
		return packet
	}
	p := pair{sender, destination}
	if p.a > p.b {
		p.a, p.b = p.b, p.a
	}
	s := e.pairs[p]
	if packet[1] != 2 {
		if s != nil {
			s.lastSeen = now // the separate match protocol keeps this pair active
		}
		return packet
	}
	if s == nil || now.Sub(s.lastSeen) > pairTTL {
		if len(e.pairs) >= maxPairs {
			for k, v := range e.pairs {
				if now.Sub(v.lastSeen) > pairTTL {
					delete(e.pairs, k)
				}
			}
			if len(e.pairs) >= maxPairs {
				return packet
			}
		}
		s = &association{pubs: map[int]publicKey{}, ips: map[int]netip.Addr{}, sequence: map[int]uint32{}}
		e.pairs[p] = s
	}
	s.lastSeen = now
	s.ips[sender], s.ips[destination] = senderControl.Addr(), destinationControl.Addr()
	if packet[0] == 1 && len(packet) == 8 {
		tag := binary.LittleEndian.Uint16(packet[6:])
		if s.initTag != tag {
			s.initTag, s.key, s.room, s.tried = tag, nil, nil, false
			clear(s.pubs)
			clear(s.sequence)
		}
	}
	if packet[0] == 3 && len(packet) == 169 || packet[0] == 4 && len(packet) == 106 {
		pub, ok := parsePublic(packet[len(packet)-100:])
		if !ok {
			return packet
		}
		if old, ok := s.pubs[sender]; ok && !pub.equal(old) {
			s.key, s.tried = nil, false
		}
		s.pubs[sender] = pub
		if packet[0] == 3 {
			id := [8]byte(packet[61:69])
			if id != s.roomID {
				s.roomID, s.key, s.tried = id, nil, false
			}
		}
		e.resolve(s, sender, destination, now)
		return packet
	}
	if packet[0] != 6 || len(packet) < 16 || len(s.key) != 24 {
		return packet
	}
	mac := hmac.New(sha1.New, s.key)
	mac.Write(packet[:6])
	mac.Write(packet[16:])
	if !hmac.Equal(mac.Sum(nil)[:8], packet[6:14]) {
		return packet
	}
	length := int(binary.LittleEndian.Uint16(packet[14:]))
	padded := (length + 7) &^ 7
	if 16+padded > len(packet) {
		return packet
	}
	wire := uint32(binary.LittleEndian.Uint16(packet[4:]))
	high := s.sequence[sender]
	sequence := high&^0xffff | wire
	if sequence+0x8000 < high {
		sequence += 0x10000
	} else if sequence > high+0x8000 && sequence >= 0x10000 {
		sequence -= 0x10000
	}
	s.sequence[sender] = max(high, sequence)
	iv := dwcrypto.SeedIV(sequence)
	plain, err := dwcrypto.Decrypt(s.key, iv, packet[16:16+padded])
	if err != nil {
		return packet
	}
	new, count := rewritePacket(plain[:length], s.roomID, s.room, senderVirtual)
	if count == 0 {
		return packet
	}
	copy(plain, new)
	ciphertext, err := dwcrypto.Encrypt(s.key, iv, plain)
	if err != nil {
		return packet
	}
	out := bytes.Clone(packet)
	copy(out[16:], ciphertext)
	mac.Reset()
	mac.Write(out[:6])
	mac.Write(out[16:])
	copy(out[6:14], mac.Sum(nil)[:8])
	s.rewritten += count
	e.Log.Info("match relay address rewritten", "room", s.roomID, "sender", sender,
		"destination", destination, "endpoint", senderVirtual, "copies", count)
	return out
}
