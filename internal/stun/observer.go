package stun

import (
	"encoding/hex"
	"net/netip"
	"time"
)

// BeginObservation binds subsequent receipts to one fresh room generation and
// invalidates proofs from an earlier room, even if traversal bytes are reused.
func (s *Server) BeginObservation(room [8]byte, host netip.AddrPort, started time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.router == nil || s.router.adaptive == nil {
		return
	}
	ad := s.router.adaptive
	id, ok := ad.relay.controls[host]
	if !ok {
		return
	}
	ad.observers[id] = observerGeneration{room, started}
	for key, at := range ad.attempts {
		if key.a == id || key.b == id {
			at.directReceipt = false
		}
	}
}

// ObserveConnectivity receives a room owner's native-count completion report.
// Room-key disclosure must identify one gateway client, and its IP must identify
// exactly one registered non-host endpoint. Ambiguous cases remain unmeasured.
// An active relay admission prevents a direct claim. Direct evidence suppresses
// additional offers only for the same outstanding signed traversal.
func (s *Server) ObserveConnectivity(room [8]byte, host netip.AddrPort, guestIP netip.Addr, started, at time.Time, uniqueGuest bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.router == nil || s.router.adaptive == nil {
		return
	}
	ad := s.router.adaptive
	r := ad.relay
	a, ok := r.controls[host]
	if !ok || at.Before(started) || time.Since(at) > 2*time.Second || at.After(time.Now().Add(250*time.Millisecond)) {
		return
	}
	generation, ok := ad.observers[a]
	if !ok || generation.room != room || !generation.started.Equal(started) {
		return
	}
	reason := ""
	if !uniqueGuest || !guestIP.IsValid() {
		reason = "room key disclosed to zero or multiple guest connections"
	}
	var candidates []int
	if reason == "" {
		for id, c := range r.clients {
			if id != a && c.control.Addr() == guestIP && at.Sub(c.lastSeen) <= relayTTL {
				candidates = append(candidates, id)
			}
		}
		if len(candidates) != 1 {
			reason = "guest IP does not identify one registered endpoint"
		}
	}
	if reason != "" {
		s.Log.Info("native peer count reported", "room", hex.EncodeToString(room[:]), "path", "unmeasured", "reason", reason)
		return
	}
	b := candidates[0]
	if ad.allows(a, b, at) {
		s.Log.Info("native mesh completion observed", "room", hex.EncodeToString(room[:]), "a", a, "b", b, "path", "relay-available")
		return
	}
	bound := false
	for _, key := range []pair{{a, b}, {b, a}} {
		if attempt := ad.attempts[key]; attempt != nil && !attempt.first.Before(started) && !attempt.last.After(at) {
			attempt.directReceipt = true
			attempt.pendingOffer = false
			bound = true
		}
	}
	s.Log.Info("native mesh completion observed", "room", hex.EncodeToString(room[:]), "a", a, "b", b, "path", "direct", "current_traversal", bound)
}
