package stun

import (
	"bytes"
	"log/slog"
	"net/netip"
	"time"
)

// Adaptive mode: discovery reports real endpoints and Moderate NAT, so peers
// connect through the native introduction. Each introduction is forwarded as in
// direct mode while both relay mappings are proved in the background. If the
// connector asks again after the direct window, it is sent its own signed request
// back as a 0x0c from the target's virtual endpoint; the client checks its own
// authenticator and adopts that UDP source as the peer, so whichever path answers
// first wins.
const (
	attemptTTL    = 6 * time.Second
	offerInterval = 400 * time.Millisecond
)

var maxAttempts = 1024 // a variable for tests

type attempt struct {
	a, b          int
	packet        []byte
	first, last   time.Time
	requests      int
	pendingOffer  bool
	offered       time.Time
	offers        int
	directReceipt bool // a current native mesh observer verified completion
}

type adaptive struct {
	relay     *relay
	log       *slog.Logger
	window    time.Duration
	attempts  map[pair]*attempt // (connector, target)
	offered   map[pair]time.Time
	observers map[int]observerGeneration
}

type observerGeneration struct {
	room    [8]byte
	started time.Time
}

func newAdaptive(r *relay, log *slog.Logger, window time.Duration) *adaptive {
	a := &adaptive{relay: r, log: log, window: window, attempts: map[pair]*attempt{}, offered: map[pair]time.Time{}, observers: map[int]observerGeneration{}}
	r.allowPair = a.allows
	return a
}

// allows reports whether a pair was offered a relay route and is still active.
func (ad *adaptive) allows(a, b int, now time.Time) bool {
	key := sorted(a, b)
	offered, ok := ad.offered[key]
	if !ok || ad.relay.clients[a] == nil || ad.relay.clients[b] == nil {
		return false
	}
	activity := offered
	if f := ad.relay.flows[key]; f != nil && f.lastSeen.After(activity) {
		activity = f.lastSeen
	}
	return now.Sub(activity) <= relayTTL
}

func (ad *adaptive) introduce(req request, from netip.AddrPort, now time.Time) []Outbound {
	r := ad.relay
	a, okA := r.controls[from]
	b, okB := r.controls[req.dst]
	reason := ""
	switch {
	case req.src != from:
		reason = "source mapping mismatch"
	case !okA || !okB:
		reason = "endpoint not registered"
	case a == b:
		reason = "self target"
	case now.Sub(r.clients[a].lastSeen) > relayTTL || now.Sub(r.clients[b].lastSeen) > relayTTL:
		reason = "registration expired"
	}
	if reason != "" {
		ad.log.Info("introduction blocked", "reason", reason, "from", from, "source", req.src, "target", req.dst)
		return nil
	}
	direct := Outbound{primary, r.clients[b].control, forwardIntro(req.raw), "adaptive-direct-introduction"}
	key := pair{a, b}
	at := ad.attempts[key]
	fresh := at == nil
	// A bounded lifetime gives later joins a fresh direct window even when the
	// game reuses an identical signed request.
	if at != nil && (now.Sub(at.first) > attemptTTL || !bytes.Equal(req.raw, at.packet)) {
		delete(ad.attempts, key)
		at, fresh = nil, true
	}
	if at == nil {
		if len(ad.attempts) >= maxAttempts {
			ad.log.Warn("adaptive attempt capacity")
			return []Outbound{direct}
		}
		at = &attempt{a: a, b: b, packet: append([]byte(nil), req.raw...), first: now, last: now, requests: 1}
		ad.attempts[key] = at
		ad.log.Info("introduction", "a", a, "b", b, "source", from, "target", req.dst)
	} else {
		at.requests++
		at.last = now
	}
	r.keepalive(from, now)
	// Require fresh proofs for a new traversal rather than reusing mappings an
	// earlier join cached; a client may have restarted on the same endpoint.
	out := r.preparePair(a, b, now, fresh)
	out = append(out, direct)
	if at.requests >= 2 && now.Sub(at.first) >= ad.window {
		at.pendingOffer = true
		out = append(out, ad.offer(at, now)...)
	}
	return out
}

func (ad *adaptive) offer(at *attempt, now time.Time) []Outbound {
	if at.directReceipt || !at.pendingOffer || !at.offered.IsZero() && now.Sub(at.offered) < offerInterval {
		return nil
	}
	target, ok1 := ad.relay.mapping(at.a, at.b, now)
	_, ok2 := ad.relay.mapping(at.b, at.a, now)
	if !ok1 || !ok2 {
		return nil // wait for both probes; tick retries
	}
	at.pendingOffer = false
	at.offered = now
	at.offers++
	ad.offered[sorted(at.a, at.b)] = now
	ad.log.Info("relay route offered", "a", at.a, "b", at.b, "route", ad.relay.clients[at.b].virtual, "delivery", target)
	return []Outbound{{Listener{Relay: at.b}, target, append([]byte{introReply}, at.packet[1:]...), "adaptive-relay-resolution"}}
}

func (ad *adaptive) tick(now time.Time) []Outbound {
	var out []Outbound
	for key, at := range ad.attempts {
		if now.Sub(at.first) > attemptTTL || ad.relay.clients[at.a] == nil || ad.relay.clients[at.b] == nil {
			delete(ad.attempts, key)
			ad.log.Debug("introduction attempt ended", "a", at.a, "b", at.b, "requests", at.requests, "offers", at.offers)
		} else {
			out = append(out, ad.offer(at, now)...)
		}
	}
	for key := range ad.offered {
		if !ad.allows(key.a, key.b, now) {
			delete(ad.offered, key)
		}
	}
	for id := range ad.observers {
		if ad.relay.clients[id] == nil {
			delete(ad.observers, id)
		}
	}
	return out
}
