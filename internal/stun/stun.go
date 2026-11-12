// Package stun implements DemonWare's UDP NAT services (bdIPDiscoveryClient,
// bdNATTypeDiscoveryClient, bdNATTravClient) for several titles at once, each on
// its own pair of ports, from one public IPv4 address. The relay and adaptive
// modes are a port of codstun, written for Call of Duty 2: Big Red One.
//
//	0x1e IP request             -> 0x1f: observed (or virtual) endpoint
//	0x14 NAT request, u8 flags  -> 0x15: observed endpoint, alternate endpoint
//	0x0a introduction           -> 0x0b to the target (signed bytes unchanged)
//	0x0e keepalive, every 15 s from hosts
//
// SvR 2007 uses UDP 3074/3075; BRO uses 2273/2274.
package stun

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const tickInterval = 100 * time.Millisecond

// Server runs one title's Router on real sockets.
type Server struct {
	Config
	Bind string
	Log  *slog.Logger

	mu     sync.Mutex
	router *Router
	ports  [2]*net.UDPConn
	relays map[int]*net.UDPConn
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Validate(); err != nil {
		return err
	}
	s.relays = map[int]*net.UDPConn{}
	s.router = NewRouter(s.Config, s.Log, s.allocate, s.release)
	for i, port := range []int{s.Port, s.AltPort} {
		c, err := listen(s.Bind, port)
		if err != nil {
			s.closeAll()
			return err
		}
		s.ports[i] = c
	}
	s.Log.Info("stun listening", "udp", []int{s.Port, s.AltPort}, "mode", s.Mode)

	var wg sync.WaitGroup
	for i, c := range s.ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.read(c, func(b []byte, from netip.AddrPort) []Outbound {
				return s.router.Route(b, from, Listener{Alt: i == 1}, time.Now())
			})
		}()
	}
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.closeAll()
			wg.Wait()
			return ctx.Err()
		case <-t.C:
			s.mu.Lock()
			out := s.router.Tick(time.Now())
			s.dispatch(out)
		}
	}
}

func listen(bind string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp4", addr)
}

// read passes each datagram to handle under the lock and sends its replies.
func (s *Server) read(c *net.UDPConn, handle func([]byte, netip.AddrPort) []Outbound) {
	buf := make([]byte, maxDatagram+1)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		s.mu.Lock()
		s.dispatch(handle(buf[:n], from))
	}
}

// dispatch resolves each reply's socket, releases the lock, and sends.
func (s *Server) dispatch(out []Outbound) {
	conns := make([]*net.UDPConn, len(out))
	for i, o := range out {
		switch {
		case o.From.Relay != 0:
			conns[i] = s.relays[o.From.Relay]
		case o.From.Alt:
			conns[i] = s.ports[1]
		default:
			conns[i] = s.ports[0]
		}
	}
	s.mu.Unlock()
	for i, o := range out {
		if conns[i] == nil {
			continue
		}
		if _, err := conns[i].WriteToUDPAddrPort(o.Payload, o.To); err != nil {
			s.Log.Debug("udp send failed", "to", o.To, "reason", o.Reason, "err", err)
		}
	}
}

// allocate binds the first free port in the relay range (called with s.mu held).
// Ports held by another title's relay fail to bind and are skipped.
func (s *Server) allocate(id int) (netip.AddrPort, error) {
	var err error
	for port := s.RelayLo; port <= s.RelayHi; port++ {
		var c *net.UDPConn
		if c, err = listen(s.Bind, port); err != nil {
			continue
		}
		s.relays[id] = c
		go s.read(c, func(b []byte, from netip.AddrPort) []Outbound {
			return s.router.ReceiveRelay(id, b, from, time.Now())
		})
		return netip.AddrPortFrom(s.PublicIP, uint16(port)), nil
	}
	return netip.AddrPort{}, err
}

func (s *Server) release(id int) {
	if c := s.relays[id]; c != nil {
		c.Close()
		delete(s.relays, id)
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.router.Close()
	for _, c := range s.ports {
		if c != nil {
			c.Close()
		}
	}
}
