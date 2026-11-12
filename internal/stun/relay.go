package stun

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"time"
)

// The relay gives every registered client a virtual endpoint (a UDP port on this
// host) and forwards opaque peer traffic between them. Before forwarding to a
// client it must learn which NAT mapping that client uses toward each peer's
// virtual endpoint: it sends the client (via its control endpoint) a type 0x0b
// traversal packet naming the peer's virtual endpoint and a random 80-bit
// authenticator, and the game's 0x0b handler answers that endpoint with 0x0c and
// the same bytes. The echo proves the mapping; signed game packets are never
// rewritten.
const (
	relayTTL       = 180 * time.Second
	probeLifetime  = 3 * time.Second
	probeInterval  = 500 * time.Millisecond
	probeSends     = 4
	bufferLifetime = 6 * time.Second
	maxDatagram    = 2048
	maxPending     = 64
	maxBuffered    = 16
	unknownBurst   = 40.0 // packets from unmapped sources per destination, refilled 20/s
	unknownRate    = 20.0
	flowReport     = 10 * time.Second
)

type relayClient struct {
	id       int
	control  netip.AddrPort // the endpoint discovery saw
	virtual  netip.AddrPort // the relay endpoint advertised to peers
	lastSeen time.Time
}

type pair struct{ a, b int }

func sorted(a, b int) pair {
	if a > b {
		a, b = b, a
	}
	return pair{a, b}
}

type mapping struct {
	addr netip.AddrPort
	seen time.Time
}

type probe struct {
	client, destination int
	instruction         []byte
	created, lastSent   time.Time
	sends               int
}

type pendingKey struct {
	destination int
	from        netip.AddrPort
}

type pending struct {
	created    time.Time
	packets    [][]byte
	candidates map[int]bool
	dropped    int
}

type flow struct {
	created, lastSeen, lastReport time.Time
	packets, bytes                [2]int
}

type introduction struct {
	a, b int
	at   time.Time
}

type relay struct {
	allocate func(id int) (netip.AddrPort, error)
	release  func(id int)
	log      *slog.Logger
	max      int

	clients       map[int]*relayClient
	controls      map[netip.AddrPort]int
	virtuals      map[netip.AddrPort]int
	mappings      map[pair]mapping // (client, destination) -> client's mapping toward destination's endpoint
	sources       map[pendingKey]int
	probes        map[string]*probe // keyed by the expected 0x0c echo
	pending       map[pendingKey]*pending
	flows         map[pair]*flow
	introductions map[string]introduction // expected native 0x0c replies
	budgets       map[int]bucket
	nextID        int

	// allowPair, when set (adaptive mode), limits forwarding to offered pairs.
	allowPair func(a, b int, now time.Time) bool
}

func newRelay(allocate func(int) (netip.AddrPort, error), release func(int), log *slog.Logger, max int) *relay {
	return &relay{allocate: allocate, release: release, log: log, max: max, nextID: 1,
		clients: map[int]*relayClient{}, controls: map[netip.AddrPort]int{}, virtuals: map[netip.AddrPort]int{},
		mappings: map[pair]mapping{}, sources: map[pendingKey]int{}, probes: map[string]*probe{},
		pending: map[pendingKey]*pending{}, flows: map[pair]*flow{}, introductions: map[string]introduction{},
		budgets: map[int]bucket{}}
}

func (r *relay) allowed(a, b int, now time.Time) bool {
	return r.allowPair == nil || r.allowPair(a, b, now)
}

// register returns the client for a control endpoint, allocating one and its
// virtual endpoint on first sight; nil when full.
func (r *relay) register(from netip.AddrPort, now time.Time) *relayClient {
	if id, ok := r.controls[from]; ok {
		c := r.clients[id]
		c.lastSeen = now
		return c
	}
	if len(r.clients) >= r.max {
		r.log.Warn("relay full", "clients", len(r.clients), "from", from)
		return nil
	}
	id := r.nextID
	r.nextID++
	virtual, err := r.allocate(id)
	if err != nil {
		r.log.Error("relay endpoint allocation failed", "err", err)
		return nil
	}
	c := &relayClient{id, from, virtual, now}
	r.clients[id], r.controls[from], r.virtuals[virtual] = c, id, id
	r.log.Info("relay client registered", "client", id, "control", from, "virtual", virtual)
	return c
}

func (r *relay) keepalive(from netip.AddrPort, now time.Time) {
	if id, ok := r.controls[from]; ok {
		r.clients[id].lastSeen = now
	}
}

func (r *relay) mapping(client, destination int, now time.Time) (netip.AddrPort, bool) {
	m, ok := r.mappings[pair{client, destination}]
	if ok && now.Sub(m.seen) <= relayTTL {
		return m.addr, true
	}
	return netip.AddrPort{}, false
}

// preparePair probes both directions of a pair that lack a mapping; refresh
// discards existing mappings first (a new traversal may follow a restart).
func (r *relay) preparePair(a, b int, now time.Time, refresh bool) []Outbound {
	var out []Outbound
	for _, p := range []pair{{a, b}, {b, a}} {
		if refresh {
			if old, ok := r.mappings[p]; ok {
				delete(r.mappings, p)
				delete(r.sources, pendingKey{p.b, old.addr})
			}
		}
		if _, ok := r.mapping(p.a, p.b, now); !ok {
			out = append(out, r.probe(p.a, p.b, now)...)
		}
	}
	return out
}

func (r *relay) allowUnknown(destination int, now time.Time) bool {
	b, ok := r.budgets[destination]
	if !ok {
		b = bucket{unknownBurst, now}
	}
	tokens := min(unknownBurst, b.tokens+max(0, now.Sub(b.last).Seconds())*unknownRate)
	r.budgets[destination] = bucket{max(0, tokens-1), now}
	return tokens >= 1
}

// probe asks client to send a 0x0c echo to destination's virtual endpoint.
func (r *relay) probe(client, destination int, now time.Time) []Outbound {
	if client == destination {
		return nil
	}
	for _, p := range r.probes {
		if p.client == client && p.destination == destination {
			return nil
		}
	}
	if len(r.probes) >= r.max*4 {
		r.log.Warn("relay probe capacity", "client", client, "destination", destination)
		return nil
	}
	c, remote := r.clients[client], r.clients[destination]
	var auth [10]byte
	var id [4]byte
	rand.Read(auth[:])
	rand.Read(id[:])
	// The authenticator is an echo challenge: the 0x0b handler copies it into
	// its reply without verifying it.
	instruction := traversalPacket(introForward, binary.LittleEndian.Uint32(id[:]), remote.virtual, c.virtual, auth)
	expected := append([]byte{introReply}, instruction[1:]...)
	r.probes[string(expected)] = &probe{client, destination, instruction, now, now, 1}
	r.log.Debug("relay probe sent", "client", client, "destination", destination, "control", c.control)
	return []Outbound{{primary, c.control, instruction, "relay-mapping-probe"}}
}

func (r *relay) learn(client, destination int, from netip.AddrPort, now time.Time) {
	p := pair{client, destination}
	if old, ok := r.mappings[p]; ok {
		delete(r.sources, pendingKey{destination, old.addr})
	}
	r.mappings[p] = mapping{from, now}
	r.sources[pendingKey{destination, from}] = client
	r.clients[client].lastSeen = now
	r.log.Debug("relay mapping proved", "client", client, "destination", destination, "observed", from)
}

func (r *relay) deliver(sender, destination int, from netip.AddrPort, packet []byte, now time.Time) []Outbound {
	if sender == destination || !r.allowed(sender, destination, now) {
		return nil
	}
	r.mappings[pair{sender, destination}] = mapping{from, now}
	r.clients[sender].lastSeen = now
	target, ok := r.mapping(destination, sender, now)
	if !ok {
		return r.probe(destination, sender, now)
	}
	key := sorted(sender, destination)
	f, ok := r.flows[key]
	if !ok {
		f = &flow{created: now, lastReport: now}
		r.flows[key] = f
		r.log.Info("relay flow started", "a", key.a, "b", key.b)
	}
	side := 0
	if sender != key.a {
		side = 1
	}
	f.packets[side]++
	f.bytes[side] += len(packet)
	f.lastSeen = now
	return []Outbound{{Listener{Relay: sender}, target, packet, "relay-data"}}
}

// flush delivers buffered packets whose source mapping has since been proved.
func (r *relay) flush(now time.Time) []Outbound {
	var out []Outbound
	for key, p := range r.pending {
		sender, ok := r.sources[key]
		if !ok || r.clients[sender] == nil {
			continue
		}
		if !r.allowed(sender, key.destination, now) {
			delete(r.pending, key)
			continue
		}
		if _, ok := r.mapping(key.destination, sender, now); !ok {
			out = append(out, r.probe(key.destination, sender, now)...)
			continue
		}
		delete(r.pending, key)
		for _, packet := range p.packets {
			out = append(out, r.deliver(sender, key.destination, key.from, packet, now)...)
		}
	}
	return out
}

func (r *relay) receive(destination int, packet []byte, from netip.AddrPort, now time.Time) []Outbound {
	if r.clients[destination] == nil || len(packet) == 0 || len(packet) > maxDatagram {
		return r.drop("destination gone, empty or oversized", destination, from, packet)
	}
	if p, ok := r.probes[string(packet)]; ok {
		if p.destination != destination || now.Sub(p.created) > probeLifetime {
			return r.drop("probe echo on the wrong endpoint or expired", destination, from, packet)
		}
		delete(r.probes, string(packet))
		r.learn(p.client, destination, from, now)
		return r.flush(now)
	}
	// Forward a native 0x0c only if it answers an introduction seen here; other
	// echoes may be delayed or replayed mapping challenges.
	if packet[0] == introReply && len(packet) == traversalSize {
		in, ok := r.introductions[string(packet)]
		if !ok || in.a != destination || now.Sub(in.at) > bufferLifetime {
			return r.drop("unmatched 0x0c", destination, from, packet)
		}
	}
	key := pendingKey{destination, from}
	sender, known := r.sources[key]
	if known && !r.allowed(sender, destination, now) {
		return r.drop("pair not offered", destination, from, packet)
	}
	if !known {
		if !r.allowUnknown(destination, now) {
			return r.drop("unknown source rate limit", destination, from, packet)
		}
		if r.allowPair != nil && !r.anyAllowed(destination, now) {
			return r.drop("no offered peer", destination, from, packet)
		}
	}
	if known && r.clients[sender] != nil {
		if _, ok := r.mapping(destination, sender, now); ok {
			return r.deliver(sender, destination, from, packet, now)
		}
	}
	p := r.pending[key]
	if p == nil {
		if len(r.pending) >= maxPending {
			r.log.Warn("relay pending capacity", "destination", destination)
			return nil
		}
		p = &pending{created: now, candidates: map[int]bool{}}
		r.pending[key] = p
		r.log.Debug("relay source unmapped", "destination", destination, "observed", from)
	}
	if len(p.packets) == maxBuffered {
		p.packets = p.packets[1:]
		p.dropped++
	}
	p.packets = append(p.packets, append([]byte(nil), packet...))
	if known {
		return r.probe(destination, sender, now)
	}
	// Probe every candidate rather than equating public IP with identity: CGNAT
	// can share an IP or pick different IPs per destination.
	var out []Outbound
	for id := range r.clients {
		if id != destination && !p.candidates[id] && r.allowed(id, destination, now) {
			if created := r.probe(id, destination, now); created != nil {
				p.candidates[id] = true
				out = append(out, created...)
			}
		}
	}
	return out
}

func (r *relay) drop(reason string, destination int, from netip.AddrPort, packet []byte) []Outbound {
	kind := -1
	if len(packet) > 0 {
		kind = int(packet[0])
	}
	r.log.Debug("relay packet dropped", "reason", reason, "destination", destination, "from", from,
		"type", kind, "bytes", len(packet))
	return nil
}

func (r *relay) anyAllowed(destination int, now time.Time) bool {
	for id := range r.clients {
		if id != destination && r.allowed(id, destination, now) {
			return true
		}
	}
	return false
}

// introduce handles a 0x0a in always-relay mode, where both endpoints in it are
// virtual: it probes both mappings and forwards the signed request unchanged.
func (r *relay) introduce(req request, from netip.AddrPort, now time.Time) []Outbound {
	sender, ok1 := r.controls[from]
	destination, ok2 := r.virtuals[req.dst]
	if !ok1 || !ok2 || req.src != r.clients[sender].virtual {
		r.log.Info("relay introduction rejected", "from", from, "source", req.src, "target", req.dst)
		return nil
	}
	out := r.probe(sender, destination, now)
	out = append(out, r.probe(destination, sender, now)...)
	r.introductions[string(append([]byte{introReply}, req.raw[1:]...))] = introduction{sender, destination, now}
	if len(r.introductions) > maxPending {
		oldest := ""
		for k, in := range r.introductions {
			if oldest == "" || in.at.Before(r.introductions[oldest].at) {
				oldest = k
			}
		}
		delete(r.introductions, oldest)
	}
	r.log.Info("relay introduction", "a", sender, "b", destination)
	return append(out, Outbound{primary, r.clients[destination].control, forwardIntro(req.raw), "relay-native-introduction"})
}

func (r *relay) tick(now time.Time) []Outbound {
	var out []Outbound
	for k, m := range r.mappings {
		if now.Sub(m.seen) > relayTTL {
			delete(r.mappings, k)
			delete(r.sources, pendingKey{k.b, m.addr})
		}
	}
	for k, in := range r.introductions {
		if now.Sub(in.at) > bufferLifetime {
			delete(r.introductions, k)
		}
	}
	for k, p := range r.probes {
		switch {
		case now.Sub(p.created) > probeLifetime:
			delete(r.probes, k)
			r.log.Debug("relay probe unanswered", "client", p.client, "destination", p.destination, "sends", p.sends)
		case p.sends < probeSends && now.Sub(p.lastSent) >= probeInterval:
			p.lastSent = now
			p.sends++
			out = append(out, Outbound{primary, r.clients[p.client].control, p.instruction, "relay-mapping-probe-retry"})
		}
	}
	for k, p := range r.pending {
		if now.Sub(p.created) > bufferLifetime {
			delete(r.pending, k)
			r.log.Debug("relay flow unresolved", "destination", k.destination, "observed", k.from,
				"buffered", len(p.packets), "dropped", p.dropped)
		}
	}
	for k, f := range r.flows {
		if now.Sub(f.lastReport) >= flowReport {
			f.lastReport = now
			r.log.Debug("relay flow", "a", k.a, "b", k.b, "packets", f.packets, "bytes", f.bytes,
				"idle", now.Sub(f.lastSeen).Round(time.Second).String())
		}
		if now.Sub(f.lastSeen) > relayTTL {
			delete(r.flows, k)
			r.log.Info("relay flow ended", "a", k.a, "b", k.b, "packets", f.packets, "bytes", f.bytes,
				"duration", f.lastSeen.Sub(f.created).Round(time.Second).String())
		}
	}
	expired := map[int]bool{}
	for id, c := range r.clients {
		if now.Sub(c.lastSeen) > relayTTL {
			expired[id] = true
			delete(r.clients, id)
			delete(r.controls, c.control)
			delete(r.virtuals, c.virtual)
			delete(r.budgets, id)
			r.release(id)
			r.log.Info("relay client expired", "client", id, "control", c.control)
		}
	}
	if len(expired) > 0 {
		for k := range r.mappings {
			if expired[k.a] || expired[k.b] {
				delete(r.mappings, k)
			}
		}
		for k, v := range r.sources {
			if expired[k.destination] || expired[v] {
				delete(r.sources, k)
			}
		}
		for k, p := range r.probes {
			if expired[p.client] || expired[p.destination] {
				delete(r.probes, k)
			}
		}
		for k := range r.pending {
			if expired[k.destination] {
				delete(r.pending, k)
			}
		}
		for k := range r.flows {
			if expired[k.a] || expired[k.b] {
				delete(r.flows, k)
			}
		}
		for k, in := range r.introductions {
			if expired[in.a] || expired[in.b] {
				delete(r.introductions, k)
			}
		}
	}
	return out
}
