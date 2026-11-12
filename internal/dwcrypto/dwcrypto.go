// Package dwcrypto provides the two primitives DemonWare PS2 1.75 uses with its
// servers: Tiger-192 (LibTomCrypt's "tiger", the original 1996 padding) and 3DES-CBC.
package dwcrypto

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"

	"github.com/cxmcc/tiger"
)

// Tiger returns the 24-byte Tiger digest of b.
func Tiger(b []byte) []byte {
	h := tiger.New()
	h.Write(b)
	return h.Sum(nil)
}

// SeedIV is the IV the client derives from a u32 seed: Tiger of its 4 LE bytes.
func SeedIV(seed uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], seed)
	return Tiger(b[:])[:8]
}

// UserID is DemonWare's 64-bit id for an account name: the first 8 bytes of Tiger(name).
func UserID(name []byte) uint64 {
	return binary.LittleEndian.Uint64(Tiger(name)[:8])
}

func block(key []byte) (cipher.Block, error) {
	// Go accepts keys whose first two DES keys are equal, which the client's fixed
	// signup key needs (libgcrypt rejects it).
	return des.NewTripleDESCipher(key)
}

// Encrypt is 3DES-CBC over whole 8-byte blocks.
func Encrypt(key, iv, plain []byte) ([]byte, error) {
	if len(plain)%8 != 0 {
		return nil, fmt.Errorf("dwcrypto: %d bytes is not a whole number of blocks", len(plain))
	}
	b, err := block(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(b, iv[:8]).CryptBlocks(out, plain)
	return out, nil
}

// Decrypt is 3DES-CBC over whole 8-byte blocks.
func Decrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("dwcrypto: %d bytes is not a whole number of blocks", len(data))
	}
	b, err := block(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(b, iv[:8]).CryptBlocks(out, data)
	return out, nil
}
