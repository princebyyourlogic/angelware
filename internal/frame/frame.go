// Package frame implements the bdStreamSocket framing used by the auth service and
// the lobby service gateway (LBYM send 0x896d8, receive 0x8a068):
//
//	u16 LE length | u8 encrypted | ...
//	plain:     u8 message type | payload           (length = payload + 2)
//	encrypted: u32 seed | 3DES-CBC ciphertext      (length = ciphertext + 5)
//
// The ciphertext holds u32 0xDEADBEEF, the message type and the payload, padded to
// 8 bytes. The client accepts plain frames from the server in every state.
package frame

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic starts every decrypted frame body.
const Magic = 0xDEADBEEF

type Frame struct {
	Encrypted bool
	Type      uint8  // valid when !Encrypted
	Seed      uint32 // valid when Encrypted
	Payload   []byte // message payload, or the ciphertext when Encrypted
}

// Read reads one frame.
func Read(r *bufio.Reader) (Frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[:]))
	if n < 2 {
		return Frame{}, fmt.Errorf("frame: length %d too short", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	if body[0] == 1 {
		if n < 5 {
			return Frame{}, errors.New("frame: encrypted frame without seed")
		}
		return Frame{Encrypted: true, Seed: binary.LittleEndian.Uint32(body[1:]), Payload: body[5:]}, nil
	}
	return Frame{Type: body[1], Payload: body[2:]}, nil
}

// Plain encodes an unencrypted frame.
func Plain(msgType uint8, payload []byte) []byte {
	out := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint16(out, uint16(len(payload)+2))
	out[3] = msgType
	return append(out, payload...)
}

// Open checks and splits a decrypted frame body into its type and payload.
func Open(plain []byte) (uint8, []byte, error) {
	if len(plain) < 5 || binary.LittleEndian.Uint32(plain) != Magic {
		return 0, nil, errors.New("frame: bad magic after decryption")
	}
	return plain[4], plain[5:], nil
}
