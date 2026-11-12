package svrpeer

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

type bits struct {
	data []byte
	pos  int
	ok   bool
}

func (b *bits) read(n int) uint64 {
	if n < 0 || n > 64 || b.pos+n > len(b.data)*8 {
		b.ok = false
		return 0
	}
	var value uint64
	for i := range n {
		value |= uint64(b.data[(b.pos+i)/8]>>((b.pos+i)%8)&1) << i
	}
	b.pos += n
	return value
}

func (b *bits) raw(n int) []byte {
	if n < 0 || b.pos+n*8 > len(b.data)*8 {
		b.ok = false
		return nil
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(b.read(8))
	}
	return out
}

func writeBits(data []byte, position int, value []byte) {
	for i := range len(value) * 8 {
		p := position + i
		mask := byte(1 << (p % 8))
		data[p/8] = data[p/8]&^mask | (value[i/8]>>(i%8)&1)<<(p%8)
	}
}

// rewriteJoinAccept edits both the generic and game-specific host-address
// copies. Their bit positions vary with the host's name; do not byte-search IPs.
func rewriteJoinAccept(data []byte, roomID [8]byte, roomKey []byte, relay netip.AddrPort) int {
	b := bits{data: data, ok: true}
	if b.read(1) != 0 { // captured join-accept is an untyped bit buffer
		return 0
	}
	for n := 0; ; n++ {
		c := b.read(8)
		if !b.ok || n > 32 {
			return 0
		}
		if c == 0 {
			break
		}
	}
	b.read(64) // host ID
	if b.read(32) != 25 {
		return 0
	}
	addressBit := b.pos
	b.raw(25)
	if !b.ok {
		return 0
	}
	// Require the same name/ID/blob prefix and a game-specific record that
	// contains this association's room ID and key before changing either copy.
	var addresses []int
	bound := false
	prefixBits := addressBit + 200 - 1
	for start := 1; start+prefixBits <= len(data)*8; start++ {
		match := true
		for i := range prefixBits {
			p, q := start+i, 1+i
			if data[p/8]>>(p%8)&1 != data[q/8]>>(q%8)&1 {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		p := start + addressBit - 1
		addresses = append(addresses, p)
		probe := bits{data: data, pos: p + 200, ok: true}
		if probe.read(32) == 8 && bytes.Equal(probe.raw(8), roomID[:]) &&
			probe.read(32) == 16 && bytes.Equal(probe.raw(16), roomKey) && probe.ok {
			bound = true
		}
	}
	if !bound {
		return 0
	}
	packed := relay.Addr().As4()
	var endpoint [6]byte
	copy(endpoint[:], packed[:])
	binary.LittleEndian.PutUint16(endpoint[4:], relay.Port())
	for _, p := range addresses {
		writeBits(data, p, endpoint[:])
		writeBits(data, p+18*8, endpoint[:])
	}
	return len(addresses)
}

type dataChunk struct{ start, end int }

// rewritePacket accepts DATA and SACK chunks with compact clear-tail lengths.
// Unsupported layouts remain opaque; no pattern-based scanning of other chunks.
func rewritePacket(data []byte, roomID [8]byte, roomKey []byte, relay netip.AddrPort) ([]byte, int) {
	var chunks []dataChunk
	for p := 4; p < len(data); {
		tail := int(data[p])
		p++
		if tail&128 != 0 {
			if p >= len(data) {
				return nil, 0
			}
			tail = (tail&127)<<8 | int(data[p])
			p++
		}
		if p >= len(data) {
			return nil, 0
		}
		switch data[p] {
		case 2: // bdDataChunk: kind, flags, length, message type, sequence
			if p+7 > len(data) {
				return nil, 0
			}
			end := p + 7 + int(binary.LittleEndian.Uint16(data[p+2:]))
			if end > len(data) {
				return nil, 0
			}
			if data[p+4] == 0x4f && data[p+1] == 0 && tail == 0 {
				chunks = append(chunks, dataChunk{p + 7, end})
			}
			p = end
		case 5: // bdSAckChunk: fixed fields and four-byte gap ranges
			if p+15 > len(data) {
				return nil, 0
			}
			p += 15 + int(binary.LittleEndian.Uint16(data[p+11:]))*4
			if p > len(data) {
				return nil, 0
			}
		default:
			return nil, 0
		}
	}
	if len(chunks) == 0 {
		return nil, 0
	}
	out := bytes.Clone(data)
	count := 0
	for _, c := range chunks {
		count += rewriteJoinAccept(out[c.start:c.end], roomID, roomKey, relay)
	}
	return out, count
}
