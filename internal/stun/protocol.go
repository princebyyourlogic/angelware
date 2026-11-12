package stun

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ipRequest    = 0x1E
	ipReply      = 0x1F
	natRequest   = 0x14
	natReply     = 0x15
	introRequest = 0x0A
	introForward = 0x0B
	introReply   = 0x0C
	keepalive    = 0x0E

	changeIP      = 1
	changePort    = 2
	traversalSize = 29
)

var errProtocol = errors.New("not a supported discovery or traversal packet")

// request is one parsed client datagram. Discovery (0x1e, 0x14) arrives with the
// client's header version: SvR 2007 sends packed v2 (u8 type, u16 2), CoD BRO
// padded v1 (u8 type, u8 pad, u16 1; the pad byte is left uninitialised). Replies
// use the same version. Traversal (0x0a, 0x0e) is always packed v2, 29 bytes:
// type, u16 2, authenticator[10], u32 id, source addr, destination addr.
type request struct {
	kind     byte
	version  uint16
	flags    byte
	src, dst netip.AddrPort
	raw      []byte
}

func parse(b []byte) (request, error) {
	if len(b) == 0 {
		return request{}, errProtocol
	}
	r := request{kind: b[0], raw: b}
	v2 := len(b) >= 3 && b[1] == 2 && b[2] == 0
	switch r.kind {
	case ipRequest, natRequest:
		switch {
		case v2 && (r.kind == ipRequest || len(b) >= 4):
			r.version = 2
			if r.kind == natRequest {
				r.flags = b[3]
			}
		case len(b) == 4 && r.kind == ipRequest || len(b) == 8 && r.kind == natRequest:
			if b[2] != 1 || b[3] != 0 {
				return r, errProtocol
			}
			r.version = 1
			if r.kind == natRequest {
				r.flags = b[4]
			}
		default:
			return r, errProtocol
		}
		if r.flags&^(changeIP|changePort) != 0 {
			return r, errProtocol
		}
	case introRequest, keepalive:
		if !v2 || len(b) != traversalSize {
			return r, errProtocol
		}
		r.version = 2
		r.src, r.dst = unpackAddr(b[17:23]), unpackAddr(b[23:29])
	default:
		return r, errProtocol
	}
	return r, nil
}

func header(kind byte, version uint16) []byte {
	if version == 2 {
		return []byte{kind, 2, 0}
	}
	return []byte{kind, 0, 1, 0}
}

// addrField is an address as discovery replies carry it: v1 pads it to 8 bytes.
func addrField(version uint16, a netip.AddrPort) []byte {
	b := packAddr(a)
	if version == 1 {
		b = append(b, 0, 0)
	}
	return b
}

func ipReplyPacket(version uint16, observed netip.AddrPort) []byte {
	return append(header(ipReply, version), addrField(version, observed)...)
}

func natReplyPacket(version uint16, observed, alternate netip.AddrPort) []byte {
	b := append(header(natReply, version), addrField(version, observed)...)
	return append(b, packAddr(alternate)...)
}

// forwardIntro turns a 0x0a introduction into the 0x0b the target receives. The
// consoles authenticate the id and both addresses, so every other byte is kept.
func forwardIntro(raw []byte) []byte {
	return append([]byte{introForward}, raw[1:]...)
}

func traversalPacket(kind byte, id uint32, src, dst netip.AddrPort, auth [10]byte) []byte {
	b := append([]byte{kind, 2, 0}, auth[:]...)
	b = binary.LittleEndian.AppendUint32(b, id)
	b = append(b, packAddr(src)...)
	return append(b, packAddr(dst)...)
}

// packAddr writes a bdSockAddr: the IPv4 octets in order, then a u16 LE port.
func packAddr(a netip.AddrPort) []byte {
	ip := a.Addr().As4()
	return binary.LittleEndian.AppendUint16(ip[:], a.Port())
}

func unpackAddr(b []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.LittleEndian.Uint16(b[4:]))
}
