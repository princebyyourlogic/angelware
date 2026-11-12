package stun

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// network models consoles behind NATs with strict filtering: a datagram reaches
// a client only from a destination that client's mapping has contacted. EDM
// clients get a new mapping per destination (and with pooled, a different public
// IP for anything but the server's primary endpoint); EIM clients reuse one.
// Consoles answer relay probes (0x0b naming a virtual endpoint) with a 0x0c echo
// to that endpoint, as the game's handler does. Ported from codstun's tests.
type network struct {
	t        *testing.T
	primary  netip.AddrPort
	modes    []string
	pooled   bool
	nats     []map[netip.AddrPort]netip.AddrPort // per client: destination (or zero for EIM) -> mapping
	allowed  map[netip.AddrPort]map[netip.AddrPort]bool
	owners   map[netip.AddrPort]int
	router   *Router
	relay    *relay
	clients  []*relayClient
	received [][]delivery
	blocked  []Outbound
	closed   []int

	// adaptive bookkeeping: native 0x0c replies each connector still waits for,
	// and the peer endpoint it settled on.
	waiting  map[[2]int][]byte
	resolved map[[2]int]netip.AddrPort
}

type delivery struct {
	from netip.AddrPort
	data []byte
}

var payload = []byte("\x01\x02\x00\x00\x01\x00opaque-handshake")

func newNetwork(t *testing.T, mode Mode, modes []string, pooled bool) *network {
	n := &network{t: t, primary: netip.AddrPortFrom(server, 2273), modes: modes, pooled: pooled,
		allowed: map[netip.AddrPort]map[netip.AddrPort]bool{}, owners: map[netip.AddrPort]int{},
		received: make([][]delivery, len(modes)), waiting: map[[2]int][]byte{}, resolved: map[[2]int]netip.AddrPort{}}
	for range modes {
		n.nats = append(n.nats, map[netip.AddrPort]netip.AddrPort{})
	}
	cfg := Config{PublicIP: server, Port: 2273, AltPort: 2274, Mode: mode, RelayLo: 20000, RelayHi: 20199,
		RelayMaxClients: 16, DirectWindow: time.Second}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	n.router = NewRouter(cfg, discard,
		func(id int) (netip.AddrPort, error) { return netip.AddrPortFrom(server, uint16(20000+id)), nil },
		func(id int) { n.closed = append(n.closed, id) })
	n.relay = n.router.relay
	for i := range modes {
		control := n.outgoing(i, n.primary)
		out := n.router.Route(unhex("1e000100"), control, primary, t0)
		if len(out) != 1 {
			t.Fatal("no ip reply")
		}
		n.clients = append(n.clients, n.relay.clients[n.relay.controls[control]])
	}
	return n
}

func (n *network) outgoing(i int, dst netip.AddrPort) netip.AddrPort {
	key := dst
	if n.modes[i] == "EIM" {
		key = netip.AddrPort{}
	}
	m, ok := n.nats[i][key]
	if !ok {
		ip := "198.51.100.7"
		if n.pooled && dst != n.primary {
			ip = fmt.Sprintf("203.0.113.%d", i+10)
		}
		m = netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(30000+i*1000+len(n.nats[i])))
		n.nats[i][key] = m
	}
	if n.allowed[m] == nil {
		n.allowed[m] = map[netip.AddrPort]bool{}
	}
	n.allowed[m][dst] = true
	n.owners[m] = i
	return m
}

// send has client i send data to client j's virtual endpoint.
func (n *network) send(i, j int, data []byte, now time.Time) []Outbound {
	from := n.outgoing(i, n.clients[j].virtual)
	return n.router.ReceiveRelay(n.clients[j].id, data, from, now)
}

// introduction has client a (adaptive: real endpoints) ask to be introduced to b.
func (n *network) introduction(a, b int, now time.Time) []Outbound {
	src, dst := n.clients[a].control, n.clients[b].control
	n.outgoing(a, dst) // Moderate/Moderate also sends a direct request first
	packet := traversalPacket(introRequest, uint32(b+100), src, dst, [10]byte([]byte("0123456789")))
	n.waiting[[2]int{a, b}] = append([]byte{introReply}, packet[1:]...)
	return n.router.Route(packet, src, primary, now)
}

func (n *network) source(o Outbound) netip.AddrPort {
	if o.From.Relay != 0 {
		return n.relay.clients[o.From.Relay].virtual
	}
	return n.primary
}

func (n *network) pump(out []Outbound, now time.Time, answerProbes bool) {
	queue := slices.Clone(out)
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 1000 {
			n.t.Fatal("network did not quiesce")
		}
		o := queue[0]
		queue = queue[1:]
		src := n.source(o)
		if !n.allowed[o.To][src] {
			n.blocked = append(n.blocked, o)
			continue
		}
		i := n.owners[o.To]
		switch {
		case o.From.Relay == 0:
			// A 0x0b from the server: answer the named endpoint with 0x0c.
			target := unpackAddr(o.Payload[17:23])
			echo := append([]byte{introReply}, o.Payload[1:]...)
			if id, ok := n.relay.virtuals[target]; ok {
				if answerProbes {
					queue = append(queue, n.relay.receive(id, echo, n.outgoing(i, target), now)...)
				}
			} else if mapped := n.outgoing(i, target); n.allowed[target][mapped] {
				// Native direct reply to the connector's real endpoint.
				recipient := n.owners[target]
				if k := [2]int{recipient, i}; bytes.Equal(n.waiting[k], echo) {
					delete(n.waiting, k)
					n.resolved[k] = mapped
				}
			}
		case o.Payload[0] == introReply && n.isWaiting(i, o.Payload):
			for k, want := range n.waiting {
				if k[0] == i && bytes.Equal(o.Payload, want) {
					delete(n.waiting, k)
					n.resolved[k] = src
				}
			}
		default:
			n.received[i] = append(n.received[i], delivery{src, o.Payload})
		}
	}
}

func (n *network) isWaiting(i int, p []byte) bool {
	for k, want := range n.waiting {
		if k[0] == i && bytes.Equal(p, want) {
			return true
		}
	}
	return false
}

func (n *network) last(i int) delivery {
	if len(n.received[i]) == 0 {
		n.t.Fatalf("client %d received nothing", i)
	}
	return n.received[i][len(n.received[i])-1]
}

func three(m string) []string { return []string{m, m, m} }

// --- always-relay mode -------------------------------------------------------

func TestRelayAdvertisesVirtualEndpoints(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	out := n.router.Route(unhex("1e000100"), n.clients[0].control, primary, at(1))
	if got := unpackAddr(out[0].Payload[4:10]); got != n.clients[0].virtual {
		t.Fatalf("advertised %v, want virtual %v", got, n.clients[0].virtual)
	}
	// Every NAT test is answered from the primary with the second port as the
	// alternate, so the client reports Open.
	for _, flags := range []string{"00", "02", "03"} {
		out := n.router.Route(unhex("14000100"+flags+"000000"), n.clients[0].control, primary, at(1))
		if len(out) != 1 || out[0].From != primary || unpackAddr(out[0].Payload[12:18]).Port() != 2274 {
			t.Errorf("flags %s: %+v", flags, out)
		}
	}
}

func TestRelayStrictFilteringDestinationDependentAndSharedIP(t *testing.T) {
	for _, modes := range [][]string{three("EIM"), {"EDM", "EIM", "EDM"}, three("EDM")} {
		for _, pooled := range []bool{false, true} {
			n := newNetwork(t, Relay, modes, pooled)
			n.pump(n.send(0, 1, payload, at(1)), at(1.1), true)
			if got := n.last(1); got.from != n.clients[0].virtual || !bytes.Equal(got.data, payload) || len(n.received[2]) != 0 {
				t.Fatalf("%v pooled=%v: %+v", modes, pooled, n.received)
			}
			reply := []byte("\x02\x02\x00\x00\x01\x00opaque-answer")
			n.pump(n.send(1, 0, reply, at(1.2)), at(1.2), true)
			if got := n.last(0); got.from != n.clients[1].virtual || !bytes.Equal(got.data, reply) {
				t.Fatalf("%v pooled=%v: reply %+v", modes, pooled, got)
			}
			if len(n.blocked) != 0 {
				t.Fatalf("%v pooled=%v: blocked %d", modes, pooled, len(n.blocked))
			}
		}
	}
}

func TestRelayMeshConnectionsStayDistinct(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	for _, p := range [][2]int{{0, 1}, {0, 2}, {1, 2}, {2, 0}, {2, 1}, {1, 0}} {
		packet := append(slices.Clone(payload), byte(p[0]), byte(p[1]))
		n.pump(n.send(p[0], p[1], packet, at(1)), at(1.1), true)
		if got := n.last(p[1]); got.from != n.clients[p[0]].virtual || !bytes.Equal(got.data, packet) {
			t.Fatalf("%v: %+v", p, got)
		}
	}
	if len(n.relay.flows) != 3 {
		t.Fatalf("%d flows", len(n.relay.flows))
	}
}

func TestRelayProbeReplayWrongPortAndTampering(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	out := n.send(0, 1, payload, at(1))
	i := slices.IndexFunc(out, func(o Outbound) bool { return o.To == n.clients[0].control })
	echo := append([]byte{introReply}, out[i].Payload[1:]...)
	from := n.outgoing(0, n.clients[1].virtual)
	n.relay.receive(n.clients[2].id, echo, from, at(1.1)) // wrong endpoint
	corrupted := slices.Clone(echo)
	corrupted[4] ^= 1
	n.relay.receive(n.clients[1].id, corrupted, from, at(1.1))
	if len(n.relay.sources) != 0 {
		t.Fatal("mapping learned from a wrong-port or tampered echo")
	}
	n.relay.receive(n.clients[1].id, echo, from, at(1.2))
	if n.relay.sources[pendingKey{n.clients[1].id, from}] != n.clients[0].id {
		t.Fatal("valid echo not learned")
	}
	if out := n.relay.receive(n.clients[1].id, echo, from, at(1.3)); out != nil {
		t.Fatal("replayed echo forwarded")
	}
}

func TestRelayExpiryClosesSocketsAndState(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	n.pump(n.send(0, 1, payload, at(1)), at(1.1), true)
	n.router.Tick(at(1000))
	r := n.relay
	if len(r.clients)+len(r.controls)+len(r.virtuals)+len(r.mappings)+len(r.sources)+len(r.probes)+len(r.pending)+len(r.flows) != 0 {
		t.Fatal("state left after expiry")
	}
	slices.Sort(n.closed)
	if !slices.Equal(n.closed, []int{1, 2, 3}) {
		t.Fatalf("closed %v", n.closed)
	}
}

func TestRelayBounds(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	stranger := netip.MustParseAddr("203.0.113.99")
	if n.relay.receive(2, make([]byte, 2049), netip.AddrPortFrom(stranger, 3000), at(1)) != nil {
		t.Fatal("oversized datagram accepted")
	}
	for port := 1000; port < 1200; port++ {
		n.relay.receive(2, payload, netip.AddrPortFrom(stranger, uint16(port)), at(float64(port-1000)/10))
	}
	if len(n.relay.pending) > maxPending || len(n.relay.probes) > n.relay.max*4 {
		t.Fatalf("pending %d probes %d", len(n.relay.pending), len(n.relay.probes))
	}
	for range 100 {
		n.relay.receive(2, payload, netip.AddrPortFrom(stranger, 1000), at(30))
	}
	if p := n.relay.pending[pendingKey{2, netip.AddrPortFrom(stranger, 1000)}]; p == nil || len(p.packets) != maxBuffered {
		t.Fatal("buffer not capped")
	}
}

func TestRelaySignedIntroductionPreserved(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	a, b := n.clients[0], n.clients[1]
	raw := traversalPacket(introRequest, 123, a.virtual, b.virtual, [10]byte([]byte("0123456789")))
	out := n.router.Route(raw, a.control, primary, at(1))
	if last := out[len(out)-1]; !bytes.Equal(last.Payload, forwardIntro(raw)) || last.To != b.control {
		t.Fatalf("introduction %+v", last)
	}
	n.pump(out, at(1.1), true)
	want := append([]byte{introReply}, raw[1:]...)
	if !slices.ContainsFunc(n.received[0], func(d delivery) bool { return d.from == b.virtual && bytes.Equal(d.data, want) }) {
		t.Fatal("native 0x0c did not return through the relay")
	}
}

func TestRelaySourceMappingCanChange(t *testing.T) {
	n := newNetwork(t, Relay, three("EDM"), false)
	n.pump(n.send(0, 1, payload, at(1)), at(1.1), true)
	a, b := n.clients[0], n.clients[1]
	old := n.outgoing(0, b.virtual)
	n.nats[0][b.virtual] = netip.AddrPortFrom(old.Addr(), old.Port()+500)
	rebound := append(slices.Clone(payload), "rebound"...)
	n.pump(n.send(0, 1, rebound, at(2)), at(2), true)
	if got := n.last(1); got.from != a.virtual || !bytes.Equal(got.data, rebound) {
		t.Fatalf("%+v", got)
	}
	if _, ok := n.relay.sources[pendingKey{b.id, old}]; ok {
		t.Fatal("stale source kept")
	}
}

// --- adaptive mode ------------------------------------------------------------

func TestAdaptiveDiscoveryKeepsRealEndpoints(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	for _, c := range n.clients {
		out := n.router.Route(unhex("1e000100"), c.control, primary, at(1))
		if unpackAddr(out[0].Payload[4:10]) != c.control {
			t.Fatal("adaptive advertised a virtual endpoint")
		}
		for _, flags := range []string{"00", "02"} {
			out := n.router.Route(unhex("14000100"+flags+"000000"), c.control, primary, at(1))
			if len(out) != 1 || out[0].From != primary || unpackAddr(out[0].Payload[4:10]) != c.control ||
				unpackAddr(out[0].Payload[12:18]) != n.primary {
				t.Fatalf("flags %s: %+v", flags, out)
			}
		}
		if n.router.Route(unhex("1400010003000000"), c.control, primary, at(1)) != nil {
			t.Fatal("test 2 answered")
		}
	}
}

func TestAdaptiveDirectPairNeedsNoRelay(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EIM"), false)
	n.pump(n.introduction(0, 1, t0), at(0.1), true)
	if n.resolved[[2]int{0, 1}] != n.clients[1].control {
		t.Fatalf("resolved %v", n.resolved)
	}
	n.pump(n.router.Tick(at(1.5)), at(1.5), true)
	if len(n.relay.flows) != 0 || len(n.router.adaptive.offered) != 0 {
		t.Fatal("relay used for a directly reachable pair")
	}
	if n.send(0, 1, payload, at(2)) != nil || len(n.relay.pending) != 0 {
		t.Fatal("relay forwarded for a pair that was never offered")
	}
}

func TestAdaptiveStrictNATsUseOfferedRelays(t *testing.T) {
	for _, modes := range [][]string{three("EDM"), {"EIM", "EDM", "EDM"}} {
		for _, pooled := range []bool{false, true} {
			n := newNetwork(t, Adaptive, modes, pooled)
			for _, p := range [][2]int{{0, 1}, {0, 2}} {
				a, b := p[0], p[1]
				n.pump(n.introduction(a, b, t0), at(0.1), true)
				if _, ok := n.resolved[p]; ok {
					t.Fatalf("%v: direct path resolved through strict NAT", modes)
				}
				n.pump(n.introduction(a, b, at(1.1)), at(1.2), true)
				if n.resolved[p] != n.clients[b].virtual {
					t.Fatalf("%v pooled=%v %v: resolved %v", modes, pooled, p, n.resolved[p])
				}
				n.pump(n.send(a, b, payload, at(1.3)), at(1.4), true)
				if got := n.last(b); got.from != n.clients[a].virtual || !bytes.Equal(got.data, payload) {
					t.Fatalf("%v: data %+v", p, got)
				}
				answer := append(slices.Clone(payload), "answer"...)
				n.pump(n.send(b, a, answer, at(1.5)), at(1.6), true)
				if got := n.last(a); got.from != n.clients[b].virtual || !bytes.Equal(got.data, answer) {
					t.Fatalf("%v: answer %+v", p, got)
				}
			}
			if len(n.relay.flows) != 2 {
				t.Fatalf("%d flows", len(n.relay.flows))
			}
			// Proved mappings alone are not enough: 1 and 2 were never offered.
			n.pump(n.relay.preparePair(2, 3, at(2), false), at(2.1), true)
			if n.send(1, 2, payload, at(2.2)) != nil {
				t.Fatal("unoffered pair relayed")
			}
		}
	}
}

func TestAdaptiveAttemptCapacityKeepsDirectIntroductions(t *testing.T) {
	old := maxAttempts
	maxAttempts = 1
	defer func() { maxAttempts = old }()
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.introduction(0, 1, t0)
	out := n.introduction(0, 2, t0)
	if len(n.router.adaptive.attempts) != 1 || len(out) != 1 || out[0].Reason != "adaptive-direct-introduction" {
		t.Fatalf("%+v", out)
	}
}

func TestAdaptiveEarlyDuplicatesDoNotOffer(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.pump(n.introduction(0, 1, at(0)), at(0.1), true)
	n.pump(n.introduction(0, 1, at(0.2)), at(0.3), true)
	n.pump(n.router.Tick(at(1.2)), at(1.2), true)
	if len(n.router.adaptive.offered) != 0 {
		t.Fatal("offered inside the direct window")
	}
	n.router.Tick(at(6.1))
	if len(n.router.adaptive.attempts) != 0 {
		t.Fatal("attempt outlived its lifetime")
	}
}

func TestAdaptiveOfferWaitsForProofsThenRunsFromTick(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.pump(n.introduction(0, 1, t0), at(0.1), false)
	out := n.introduction(0, 1, at(1.1))
	if slices.ContainsFunc(out, func(o Outbound) bool { return o.Reason == "adaptive-relay-resolution" }) {
		t.Fatal("offered without proved mappings")
	}
	n.pump(n.router.Tick(at(1.2)), at(1.3), true)
	n.pump(n.router.Tick(at(1.4)), at(1.4), true)
	if n.resolved[[2]int{0, 1}] != n.clients[1].virtual {
		t.Fatalf("resolved %v", n.resolved)
	}
}

func TestAdaptiveOfferPreservesSignedBytesAndIsRateLimited(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.pump(n.introduction(0, 1, t0), at(0.1), true)
	out := n.introduction(0, 1, at(1.1))
	var offers []Outbound
	for _, o := range out {
		if o.Reason == "adaptive-relay-resolution" {
			offers = append(offers, o)
		}
	}
	if len(offers) != 1 || !bytes.Equal(offers[0].Payload, n.waiting[[2]int{0, 1}]) ||
		offers[0].From != (Listener{Relay: n.clients[1].id}) {
		t.Fatalf("%+v", offers)
	}
	if slices.ContainsFunc(n.introduction(0, 1, at(1.2)), func(o Outbound) bool { return o.Reason == "adaptive-relay-resolution" }) {
		t.Fatal("offer not rate limited")
	}
}

func TestAdaptiveLaterJoinGetsFreshDirectWindow(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.pump(n.introduction(0, 1, t0), at(0.1), true)
	n.pump(n.introduction(0, 1, at(1.1)), at(1.2), true)
	out := n.introduction(0, 1, at(7))
	if slices.ContainsFunc(out, func(o Outbound) bool { return o.Reason == "adaptive-relay-resolution" }) {
		t.Fatal("offered at once on a later join")
	}
	if a := n.router.adaptive.attempts[pair{1, 2}]; a == nil || a.requests != 1 {
		t.Fatal("attempt not restarted")
	}
	if _, ok := n.relay.mapping(1, 2, at(7)); ok {
		t.Fatal("stale mapping reused")
	}
}

func TestAdaptiveOfferExpiresWithIdleFlow(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	n.pump(n.introduction(0, 1, t0), at(0.1), true)
	n.pump(n.introduction(0, 1, at(1.1)), at(1.2), true)
	n.router.Tick(at(7))
	n.pump(n.send(0, 1, payload, at(100)), at(100), true)
	if !n.router.adaptive.allows(1, 2, at(181)) {
		t.Fatal("authorisation did not follow flow activity")
	}
	n.router.Route(unhex("1e000100"), n.clients[0].control, primary, at(181))
	n.router.Route(unhex("1e000100"), n.clients[1].control, primary, at(181))
	n.router.Tick(at(281))
	if len(n.router.adaptive.offered) != 0 {
		t.Fatal("idle pair still authorised")
	}
}

func TestAdaptiveBlocksBadIntroductions(t *testing.T) {
	n := newNetwork(t, Adaptive, three("EDM"), false)
	a, b := n.clients[0], n.clients[1]
	auth := [10]byte([]byte("0123456789"))
	for _, c := range []struct{ src, dst, from netip.AddrPort }{
		{b.control, a.control, a.control},                                    // source mismatch
		{a.control, a.control, a.control},                                    // self
		{a.control, netip.MustParseAddrPort("203.0.113.99:3074"), a.control}, // unregistered
	} {
		if n.router.Route(traversalPacket(introRequest, 1, c.src, c.dst, auth), c.from, primary, at(1)) != nil {
			t.Errorf("%+v forwarded", c)
		}
	}
	if n.router.Route(traversalPacket(introRequest, 1, a.control, b.control, auth), a.control, primary, at(181)) != nil {
		t.Error("expired registration forwarded")
	}
}
