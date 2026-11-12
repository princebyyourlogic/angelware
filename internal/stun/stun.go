// Package stun implements DemonWare IP and NAT-type discovery and peer introduction
// (bdIPDiscoveryClient, bdNATTypeDiscoveryClient, bdNATTravClient).
//
// SvR 2007 sends the packed version 2 header (u8 type, u16 LE version); the reply
// parsers (LBYM 0xad328, 0xadba0) accept v2 packed or v1 padded, and we answer in
// the client's version. Addresses are 4 IPv4 octets + u16 LE port.
//
//	0x1e IP request             -> 0x1f: observed endpoint
//	0x14 NAT request, u8 flags  -> 0x15: observed endpoint, alternate endpoint
//
// With one server IP the change-IP test (flags 3) is withheld; the client then runs
// test 3 (flags 2), answered from the secondary port, and settles on "Moderate".
//
// Introduction (29 bytes: type, u16 version 2, HMAC[10], u32 id, initiator addr,
// target addr): a joining player sends 0x0a; we forward it as 0x0b to the target,
// which answers the initiator directly. Hosts refresh their mapping with 0x0e every
// 15 s. The initiator must match its UDP source and the target must have been seen
// recently (as in ../codstun), so this cannot be used to send UDP anywhere.
package stun

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	ipRequest    = 0x1E
	ipReply      = 0x1F
	natRequest   = 0x14
	natReply     = 0x15
	introRequest = 0x0A
	introForward = 0x0B
	keepalive    = 0x0E

	changeIP   = 1
	changePort = 2
	introSize  = 29
	peerTTL    = 2 * time.Minute
	maxPeers   = 4096
)

type Server struct {
	PublicIP netip.Addr // advertised as the alternate endpoint's address
	Port     int        // primary (3074)
	AltPort  int        // secondary, used for NAT test 3
	Log      *slog.Logger

	primary, secondary *net.UDPConn
	mu                 sync.Mutex
	seen               map[netip.AddrPort]time.Time
}

// Run serves both UDP ports until ctx ends.
func (s *Server) Run(ctx context.Context, bind string) error {
	var err error
	s.seen = map[netip.AddrPort]time.Time{}
	if s.primary, err = listen(bind, s.Port); err != nil {
		return err
	}
	if s.secondary, err = listen(bind, s.AltPort); err != nil {
		s.primary.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		s.primary.Close()
		s.secondary.Close()
	}()
	var wg sync.WaitGroup
	for _, c := range []*net.UDPConn{s.primary, s.secondary} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.read(c)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func listen(bind string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp4", addr)
}

func (s *Server) read(c *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		s.Handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), s.send)
	}
}

func (s *Server) send(secondary bool, b []byte, to netip.AddrPort) {
	c := s.primary
	if secondary {
		c = s.secondary
	}
	c.WriteToUDPAddrPort(b, to)
}

// Handle processes one datagram; send writes from the primary or secondary port.
func (s *Server) Handle(data []byte, from netip.AddrPort, send func(secondary bool, b []byte, to netip.AddrPort)) {
	now := time.Now()
	s.mu.Lock()
	s.seen[from] = now
	if len(s.seen) > maxPeers {
		for a, t := range s.seen {
			if now.Sub(t) > peerTTL {
				delete(s.seen, a)
			}
		}
	}
	s.mu.Unlock()

	msgType, version, body, ok := parse(data)
	if !ok {
		s.Log.Debug("unknown udp packet", "from", from, "data", data)
		return
	}
	switch msgType {
	case ipRequest:
		send(false, append(header(ipReply, version), pad(version, packAddr(from))...), from)
	case natRequest:
		if len(body) < 1 {
			return
		}
		flags := body[0]
		if flags&changeIP != 0 {
			return // single server IP: let the client time out into test 3
		}
		alternate := netip.AddrPortFrom(s.PublicIP, uint16(s.Port))
		reply := append(header(natReply, version), pad(version, packAddr(from))...)
		send(flags&changePort != 0, append(reply, packAddr(alternate)...), from)
	case keepalive:
	case introRequest:
		if version == 2 && len(data) == introSize {
			s.introduce(data, from, now, send)
		}
	default:
		s.Log.Debug("unhandled udp packet", "from", from, "type", msgType, "version", version)
	}
}

func (s *Server) introduce(data []byte, from netip.AddrPort, now time.Time,
	send func(bool, []byte, netip.AddrPort)) {
	initiator, target := unpackAddr(data[17:23]), unpackAddr(data[23:29])
	if initiator != from {
		s.Log.Info("introduction source mismatch", "from", from, "claims", initiator)
		return
	}
	s.mu.Lock()
	last, ok := s.seen[target]
	s.mu.Unlock()
	if !ok || target == from || now.Sub(last) > peerTTL {
		s.Log.Info("introduction target not seen recently", "from", from, "target", target)
		return
	}
	s.Log.Info("introduction forwarded", "from", from, "target", target)
	out := append([]byte{introForward}, data[1:]...)
	send(false, out, target)
}

func parse(b []byte) (msgType uint8, version uint16, body []byte, ok bool) {
	if len(b) < 3 {
		return
	}
	if v := binary.LittleEndian.Uint16(b[1:]); v == 2 {
		return b[0], 2, b[3:], true
	}
	if len(b) >= 4 && binary.LittleEndian.Uint16(b[2:]) == 1 {
		return b[0], 1, b[4:], true
	}
	return
}

func header(msgType uint8, version uint16) []byte {
	if version == 2 {
		return []byte{msgType, 2, 0}
	}
	return []byte{msgType, 0, 1, 0}
}

// pad appends v1's two padding bytes after an address.
func pad(version uint16, addr []byte) []byte {
	if version == 2 {
		return addr
	}
	return append(addr, 0, 0)
}

func packAddr(a netip.AddrPort) []byte {
	ip := a.Addr().As4()
	return binary.LittleEndian.AppendUint16(ip[:], a.Port())
}

func unpackAddr(b []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.LittleEndian.Uint16(b[4:]))
}
