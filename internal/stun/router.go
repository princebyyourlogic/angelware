package stun

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// Mode selects how peers reach each other.
type Mode string

const (
	// Direct forwards introductions; peers connect point to point.
	Direct Mode = "direct"
	// Relay advertises a virtual endpoint on this host for every client and
	// carries all peer traffic (logical Open NAT).
	Relay Mode = "relay"
	// Adaptive keeps real endpoints and coordinated (Moderate) discovery, lets
	// the native introduction try first, and offers a relay route when the
	// connector asks again after DirectWindow.
	Adaptive Mode = "adaptive"
)

// Config describes one title's STUN service on a single public IPv4 address.
type Config struct {
	PublicIP        netip.Addr
	Port, AltPort   int
	Mode            Mode
	RelayLo         int // virtual endpoint port range (relay and adaptive)
	RelayHi         int
	RelayMaxClients int
	DirectWindow    time.Duration // adaptive only
}

const (
	peerTTL    = 2 * time.Minute
	maxPeers   = 16384
	bucketSize = 100.0 // discovery packets per source IP, refilled at bucketRate/s
	bucketRate = 50.0
)

func (c Config) Validate() error {
	if !c.PublicIP.Is4() || c.PublicIP.IsUnspecified() || c.PublicIP.IsMulticast() {
		return errors.New("public address must be a unicast IPv4 address")
	}
	if c.Port < 1 || c.Port > 65535 || c.AltPort < 1 || c.AltPort > 65535 || c.Port == c.AltPort {
		return errors.New("ports must be two distinct values in 1..65535")
	}
	switch c.Mode {
	case Direct:
		return nil
	case Relay, Adaptive:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	inRange := func(p int) bool { return c.RelayLo <= p && p <= c.RelayHi }
	if c.RelayLo < 1 || c.RelayHi > 65535 || c.RelayLo > c.RelayHi || inRange(c.Port) || inRange(c.AltPort) {
		return errors.New("relay port range must be valid and exclude the discovery ports")
	}
	if c.RelayMaxClients < 2 || c.RelayMaxClients > min(256, c.RelayHi-c.RelayLo+1) {
		return errors.New("relay capacity must be 2..256 and fit in the relay port range")
	}
	if c.Mode == Adaptive && (c.DirectWindow < 250*time.Millisecond || c.DirectWindow > 2*time.Second) {
		return errors.New("direct window must be 0.25..2 seconds")
	}
	return nil
}

func (c Config) endpoint(alt bool) netip.AddrPort {
	if alt {
		return netip.AddrPortFrom(c.PublicIP, uint16(c.AltPort))
	}
	return netip.AddrPortFrom(c.PublicIP, uint16(c.Port))
}

// Listener names a socket: a discovery port (Relay 0, Alt picks the second) or a
// relay client's virtual endpoint.
type Listener struct {
	Relay int
	Alt   bool
}

var primary = Listener{}

type Outbound struct {
	From    Listener
	To      netip.AddrPort
	Payload []byte
	Reason  string
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Router holds one title's discovery, introduction and relay state. It does no
// I/O: callers pass each datagram with the time and send what it returns. It is
// not safe for concurrent use.
type Router struct {
	cfg      Config
	log      *slog.Logger
	peers    map[netip.AddrPort]time.Time
	buckets  map[netip.Addr]bucket
	relay    *relay
	adaptive *adaptive
}

// NewRouter builds a router; allocate binds a virtual endpoint for a relay client
// id and release closes it (both unused in direct mode).
func NewRouter(cfg Config, log *slog.Logger, allocate func(id int) (netip.AddrPort, error), release func(id int)) *Router {
	r := &Router{cfg: cfg, log: log, peers: map[netip.AddrPort]time.Time{}, buckets: map[netip.Addr]bucket{}}
	if cfg.Mode != Direct {
		r.relay = newRelay(allocate, release, log, cfg.RelayMaxClients)
	}
	if cfg.Mode == Adaptive {
		r.adaptive = newAdaptive(r.relay, log, cfg.DirectWindow)
	}
	return r
}

func (r *Router) admit(ip netip.Addr, now time.Time) bool {
	b, ok := r.buckets[ip]
	if !ok {
		b = bucket{bucketSize, now}
	}
	b.tokens = min(bucketSize, b.tokens+max(0, now.Sub(b.last).Seconds())*bucketRate)
	b.last = now
	admitted := b.tokens >= 1
	if admitted {
		b.tokens--
	}
	r.buckets[ip] = b
	return admitted
}

// Route handles a datagram received on a discovery port.
func (r *Router) Route(data []byte, from netip.AddrPort, on Listener, now time.Time) []Outbound {
	if !r.admit(from.Addr(), now) {
		r.log.Debug("discovery rate limited", "from", from)
		return nil
	}
	req, err := parse(data)
	if err != nil {
		r.log.Debug("unknown udp packet", "from", from, "data", data)
		return nil
	}
	if len(r.peers) < maxPeers {
		r.peers[from] = now
	}

	switch req.kind {
	case ipRequest:
		advertised := from
		if r.relay != nil {
			c := r.relay.register(from, now)
			if c == nil {
				return nil
			}
			if r.adaptive == nil {
				advertised = c.virtual
			}
		}
		r.log.Debug("ip discovery", "from", from, "advertised", advertised)
		return []Outbound{{on, from, ipReplyPacket(req.version, advertised), "public-address"}}

	case natRequest:
		switch {
		case r.adaptive != nil:
			// Every test is answered from the primary endpoint with the primary as
			// the alternate; withholding test 2 lets the client's own timeout and
			// test 3 settle on Moderate, which selects coordinated routing.
			if req.flags&changeIP != 0 {
				return nil
			}
			return []Outbound{{primary, from, natReplyPacket(req.version, from, r.cfg.endpoint(false)), "coordinated-nat"}}
		case r.relay != nil:
			// Virtual topology: every advertised peer is a reachable relay endpoint.
			// An alternate of the second port lets a same-socket reply from the
			// primary pass test 2 behind any NAT, so the client reports Open.
			return []Outbound{{primary, from, natReplyPacket(req.version, from, r.cfg.endpoint(true)), "virtual-nat"}}
		case req.flags&changeIP != 0:
			// One server IP: replying would falsely report Open. The client times
			// out into test 3 (change port) and settles on Moderate.
			return nil
		default:
			reply := Listener{Alt: on.Alt != (req.flags&changePort != 0)}
			return []Outbound{{reply, from, natReplyPacket(req.version, from, r.cfg.endpoint(on.Alt)), "nat"}}
		}

	case keepalive:
		if r.relay != nil {
			r.relay.keepalive(from, now)
		}
		return nil

	case introRequest:
		if r.adaptive != nil {
			return r.adaptive.introduce(req, from, now)
		}
		if r.relay != nil {
			return r.relay.introduce(req, from, now)
		}
		return r.introduceDirect(req, from, on, now)
	}
	return nil
}

// introduceDirect forwards a joiner's 0x0a to the target as 0x0b; the target then
// answers the joiner directly. The source must be the sender's own UDP endpoint
// and the target must have been seen recently (hosts refresh with 0x0e every
// 15 s), so this cannot be used to send UDP to arbitrary hosts.
func (r *Router) introduceDirect(req request, from netip.AddrPort, on Listener, now time.Time) []Outbound {
	if req.src != from {
		r.log.Info("introduction source mismatch", "from", from, "claims", req.src)
		return nil
	}
	seen, ok := r.peers[req.dst]
	if !ok || req.dst == from || now.Sub(seen) > peerTTL {
		r.log.Info("introduction target not seen recently", "from", from, "target", req.dst)
		return nil
	}
	r.log.Info("introduction forwarded", "from", from, "target", req.dst)
	return []Outbound{{on, req.dst, forwardIntro(req.raw), "peer-introduction"}}
}

// ReceiveRelay handles a datagram that arrived on relay client id's virtual endpoint.
func (r *Router) ReceiveRelay(id int, data []byte, from netip.AddrPort, now time.Time) []Outbound {
	if r.relay == nil {
		return nil
	}
	return r.relay.receive(id, data, from, now)
}

// Tick expires state and resends probes and route offers; call it a few times a second.
func (r *Router) Tick(now time.Time) []Outbound {
	for a, t := range r.peers {
		if now.Sub(t) > peerTTL {
			delete(r.peers, a)
		}
	}
	for ip, b := range r.buckets {
		if now.Sub(b.last).Seconds()*bucketRate >= bucketSize {
			delete(r.buckets, ip)
		}
	}
	var out []Outbound
	if r.relay != nil {
		out = r.relay.tick(now)
	}
	if r.adaptive != nil {
		out = append(out, r.adaptive.tick(now)...)
	}
	return out
}

// Close releases every relay endpoint.
func (r *Router) Close() {
	if r.relay != nil {
		for id := range r.relay.clients {
			r.relay.release(id)
		}
	}
}
