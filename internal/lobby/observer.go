package lobby

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
)

// ConnectivityEvent is a stock host's authenticated native-count transition,
// scoped to one room. It is not a GSS game-address test. UniqueGuest is false
// when room-key disclosure cannot identify exactly one other gateway client.
type ConnectivityEvent struct {
	Room                 [8]byte
	Host                 netip.AddrPort
	GuestIP              netip.Addr
	Started, At          time.Time
	Created, UniqueGuest bool
}

func gatewayIP(owner any) (netip.Addr, bool) {
	var addr net.Addr
	if c, ok := owner.(*Conn); ok && c != nil && c.conn != nil {
		addr = c.conn.RemoteAddr()
	} else if c, ok := owner.(interface{ RemoteAddr() net.Addr }); ok {
		addr = c.RemoteAddr()
	}
	if addr == nil {
		return netip.Addr{}, false
	}
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(ip)
	return a.Unmap(), err == nil
}

func nativePeers(info []bitbuf.Field) (int, bool) {
	if len(info) < 7 {
		return 0, false
	}
	for i := 3; i < 7; i++ {
		if info[i].Type != bitbuf.I32 || info[i].Int > 2 {
			return 0, false
		}
	}
	if info[3].Int+info[5].Int != 2 || info[4].Int > info[3].Int || info[6].Int > info[5].Int {
		return 0, false
	}
	return int(info[4].Int + info[6].Int), true
}

func (s *mmSession) noteDisclosure(owner any) {
	if owner == s.owner {
		return
	}
	if s.disclosed == nil {
		s.disclosed = owner
		s.disclosedIP, _ = gatewayIP(owner)
	} else if s.disclosed != owner {
		s.ambiguous = true
	}
}

func (s *mmSession) connectivityEvent(id [8]byte, info []bitbuf.Field, at time.Time) (ConnectivityEvent, bool) {
	e := ConnectivityEvent{Room: id, Started: s.createdAt, At: at, GuestIP: s.disclosedIP, UniqueGuest: s.disclosed != nil && !s.ambiguous && s.disclosedIP.IsValid()}
	if _, ok := nativePeers(info); !ok || len(info[0].Bytes) != 25 || info[0].Type != bitbuf.Blob || s.createdAt.IsZero() {
		return e, false
	}
	if len(s.info) == 0 || len(s.info[0].Bytes) != 25 || !bytes.Equal(info[0].Bytes[18:24], s.info[0].Bytes[18:24]) {
		return e, false
	}
	a := info[0].Bytes[18:24]
	e.Host = netip.AddrPortFrom(netip.AddrFrom4([4]byte(a[:4])), binary.LittleEndian.Uint16(a[4:]))
	ownerIP, ok := gatewayIP(s.owner)
	if !ok || e.Host.Port() == 0 || e.Host.Addr() != ownerIP {
		return e, false
	}
	return e, true
}
