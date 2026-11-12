package dwcrypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestTigerReferenceVectors(t *testing.T) {
	// Original Tiger (Anderson/Biham), matching LibTomCrypt "tiger" and libgcrypt TIGER1.
	for in, want := range map[string]string{
		"":    "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
		"abc": "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93",
	} {
		if got := hex.EncodeToString(Tiger([]byte(in))); got != want {
			t.Errorf("Tiger(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestUserIDMatchesCapturedLogin(t *testing.T) {
	// The retail game logged in account "aaaa" with id bytes a34683c0f2c6782e.
	if got := UserID([]byte("aaaa")); got != binary.LittleEndian.Uint64(unhex("a34683c0f2c6782e")) {
		t.Fatalf("UserID(aaaa) = %016x", got)
	}
}

func TestCapturedLobbyTaskDecrypts(t *testing.T) {
	// CreateProfile from the retail game, encrypted with the session key the
	// Python prototype handed out for that login (seed 0).
	key := unhex("0c78c7319266d1522a197dead9d1297f0fb4a53ef4c7d2e3")
	ct := unhex("fa75ea6f2fdb868ec07c2a0beb2402559834bf382b9c3716b6540732a10d05b3" +
		"d43f4ecb4db4ecbf28c3ffd790a24c67251e032e2a1c57a696de8064ac6404146c6c429cba4b001db63a64213ebfae96")
	plain, err := Decrypt(key, SeedIV(0), ct)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(plain) != 0xDEADBEEF || plain[4] != 8 {
		t.Fatalf("decrypted header %x", plain[:5])
	}
}

func TestWeakSignupKeyRoundTrip(t *testing.T) {
	key := append(bytes.Repeat(unhex("deadbeef"), 4), make([]byte, 8)...)
	block := bytes.Repeat([]byte{0x5a}, 0x60)
	enc, err := Encrypt(key, SeedIV(1234), block)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(key, SeedIV(1234), enc)
	if err != nil || !bytes.Equal(dec, block) {
		t.Fatalf("round trip failed: %v", err)
	}
}
