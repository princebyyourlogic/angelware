package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/princebyyourlogic/angelware/internal/auth"
	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
	"github.com/princebyyourlogic/angelware/internal/frame"
	"github.com/princebyyourlogic/angelware/internal/lobby"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
)

var signupKey = append(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 4), make([]byte, 8)...)

func newTCP(mode auth.Mode) (*TCP, *store.Memory) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, sessions := store.NewMemory(), session.NewRegistry()
	return &TCP{
		Auth:  &auth.Service{Store: st, Sessions: sessions, Mode: mode, Log: log},
		Lobby: &lobby.Server{Store: st, Sessions: sessions, Log: log, Matchmaking: lobby.NewMatchmaking(log)},
		Log:   log,
	}, st
}

// client plays the console's side of one TCP connection.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	key  []byte
	seed uint32
}

func dial(t *testing.T, s *TCP) *client {
	a, b := net.Pipe()
	go s.handle(context.Background(), b)
	t.Cleanup(func() { a.Close() })
	return &client{t: t, conn: a, r: bufio.NewReader(a)}
}

func (c *client) roundTrip(out []byte) frame.Frame {
	c.t.Helper()
	if _, err := c.conn.Write(out); err != nil {
		c.t.Fatal(err)
	}
	f, err := frame.Read(c.r)
	if err != nil {
		c.t.Fatal(err)
	}
	return f
}

func signup(name, password string) []byte {
	block := append([]byte{0xde, 0xad, 0xbd, 0xef}, make([]byte, 64)...)
	copy(block[4:], name)
	block = append(block, dwcrypto.Tiger([]byte(password))...)
	block = append(block, make([]byte, 0x60-len(block))...)
	enc, _ := dwcrypto.Encrypt(signupKey, dwcrypto.SeedIV(77), block)
	w := bitbuf.NewWriter(false).U32(77).U32(auth.TitleID).Raw(make([]byte, 8)).Raw(enc)
	return frame.Plain(0x00, w.Bytes())
}

func login(name string) []byte {
	id := binary.LittleEndian.AppendUint64(nil, dwcrypto.UserID([]byte(name)))
	return frame.Plain(0x0A, bitbuf.NewWriter(false).U32(5).U32(auth.TitleID).Raw(id).Bytes())
}

func status(t *testing.T, f frame.Frame) (*bitbuf.Reader, uint32) {
	r, _ := bitbuf.NewReader(f.Payload)
	code, err := r.U32()
	if err != nil {
		t.Fatal(err)
	}
	return r, code
}

// loginAndOpenGateway logs in like the console and returns a gateway client.
func loginAndOpenGateway(t *testing.T, s *TCP, name, password string) *client {
	reply := dial(t, s).roundTrip(login(name))
	r, code := status(t, reply)
	if reply.Type != 0x0B || code != 700 {
		t.Fatalf("login reply type %#x status %d", reply.Type, code)
	}
	seed, _ := r.U32()
	enc, _ := r.Raw(0x80)
	ticket, _ := r.Raw(0x80)
	// The console decrypts with its own Tiger(password) and checks the magic.
	block, err := dwcrypto.Decrypt(dwcrypto.Tiger([]byte(password)), dwcrypto.SeedIV(seed), enc)
	if err != nil || !bytes.Equal(block[:4], []byte{0xde, 0xad, 0xbd, 0xef}) {
		t.Fatalf("ticket block did not decrypt: %x", block[:8])
	}
	g := dial(t, s)
	g.key = block[97:121]
	hello := bitbuf.NewWriter(false).U32(binary.LittleEndian.Uint32(block[5:])).U32(seed).Raw(ticket)
	if _, err := g.conn.Write(frame.Plain(lobby.MsgHello, hello.Bytes())); err != nil {
		t.Fatal(err)
	}
	return g
}

// task sends an encrypted lobby task and returns the reply's typed reader after the
// echoed slot/seq.
func (c *client) task(service, slot, id uint8, args ...bitbuf.Field) *bitbuf.Reader {
	c.t.Helper()
	payload := bitbuf.NewWriter(true).U8(slot).U8(0).U8(id).Fields(args).Raw(make([]byte, 4)).Bytes()
	body := binary.LittleEndian.AppendUint32(nil, frame.Magic)
	body = append(append(body, service), payload...)
	body = append(body, make([]byte, (8-len(body)%8)%8)...)
	ct, _ := dwcrypto.Encrypt(c.key, dwcrypto.SeedIV(c.seed), body)
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(ct)+5))
	out = binary.LittleEndian.AppendUint32(append(out, 1), c.seed)
	c.seed++
	f := c.roundTrip(append(out, ct...))
	r, _ := bitbuf.NewReader(f.Payload)
	gotSlot, _ := r.U8()
	r.U8()
	if f.Type != 1 || gotSlot != slot {
		c.t.Fatalf("reply type %d slot %d", f.Type, gotSlot)
	}
	return r
}

func TestSignupAndVerifiedLogin(t *testing.T) {
	s, st := newTCP(auth.Verify)
	reply := dial(t, s).roundTrip(signup("aaaa", "secret"))
	if _, code := status(t, reply); reply.Type != 1 || code != 700 {
		t.Fatalf("signup reply type %d status %d", reply.Type, code)
	}
	acct, err := st.Account(context.Background(), dwcrypto.UserID([]byte("aaaa")))
	if err != nil || acct.Name != "aaaa" || !bytes.Equal(acct.PasswordTiger, dwcrypto.Tiger([]byte("secret"))) {
		t.Fatalf("stored account %+v, %v", acct, err)
	}
	if _, code := status(t, dial(t, s).roundTrip(signup("aaaa", "other"))); code == 700 {
		t.Fatal("duplicate signup accepted")
	}
	loginAndOpenGateway(t, s, "aaaa", "secret")

	if reply := dial(t, s).roundTrip(login("nobody")); reply.Type != 0x0B {
		t.Fatalf("unknown login reply type %#x", reply.Type)
	} else if _, code := status(t, reply); code == 700 {
		t.Fatal("unknown account logged in")
	}
}

func TestOpenModeLogin(t *testing.T) {
	s, _ := newTCP(auth.Open)
	reply := dial(t, s).roundTrip(login("anyone"))
	r, code := status(t, reply)
	r.U32()
	block, _ := r.Raw(0x80)
	if reply.Type != 0x11 || code != 700 || !bytes.Equal(block[:4], []byte{0xde, 0xad, 0xbd, 0xef}) {
		t.Fatalf("open login type %#x status %d block %x", reply.Type, code, block[:4])
	}
}

func sessionInfo() []bitbuf.Field {
	f := []bitbuf.Field{bitbuf.Bytes(bitbuf.Blob, make([]byte, 25)), bitbuf.Bytes(bitbuf.Blob, make([]byte, 8)),
		bitbuf.Bytes(bitbuf.Blob, make([]byte, 16))}
	for _, v := range []uint64{2, 0, 0, 0, 1} {
		f = append(f, bitbuf.Int(bitbuf.I32, v))
	}
	return append(f, bitbuf.Bytes(bitbuf.String, []byte("bbbb")), bitbuf.Int(bitbuf.I64, 1))
}

func TestHostFindAndProfiles(t *testing.T) {
	s, st := newTCP(auth.Verify)
	for _, n := range []string{"host", "guest"} {
		dial(t, s).roundTrip(signup(n, n+"pw"))
	}
	host := loginAndOpenGateway(t, s, "host", "hostpw")
	guest := loginAndOpenGateway(t, s, "guest", "guestpw")

	// Host creates a session: result is blob id[8] + blob key[16].
	r := host.task(5, 1, 1, append([]bitbuf.Field{bitbuf.Int(bitbuf.U8, 0)}, sessionInfo()...)...)
	r.U32() // error
	r.U8()  // kind
	if n, _ := r.U32(); n != 1 {
		t.Fatalf("create count %d", n)
	}
	id, _ := r.Field()

	// The guest's search returns the stored info with the assigned id.
	r = guest.task(5, 2, 5, bitbuf.Int(bitbuf.U8, 0), bitbuf.Int(bitbuf.I32, 1))
	r.U32()
	r.U8()
	if n, _ := r.U32(); n != 1 {
		t.Fatalf("find count %d", n)
	}
	info, _ := r.Fields()
	if !bytes.Equal(info[1].Bytes, id.Bytes) || string(info[8].Bytes) != "bbbb" {
		t.Fatalf("found %v", info)
	}

	// Private profile: default zeros, then what the game saves.
	guest.task(8, 3, 5, bitbuf.Int(bitbuf.U8, 0), bitbuf.Int(bitbuf.I32, 1), bitbuf.Int(bitbuf.I32, 0),
		bitbuf.Int(bitbuf.I32, 0), bitbuf.Int(bitbuf.I32, 0))
	r = guest.task(8, 4, 3, bitbuf.Int(bitbuf.U8, 0))
	r.U32()
	r.U8()
	prof, _ := r.Fields()
	if len(prof) != 5 || prof[0].Int != dwcrypto.UserID([]byte("guest")) || prof[1].Int != 1 {
		t.Fatalf("private profile %v", prof)
	}

	// A stats write is stored.
	host.task(4, 5, 1, bitbuf.Int(bitbuf.U8, 0), bitbuf.Int(bitbuf.U8, 0), bitbuf.Int(bitbuf.I32, 3),
		bitbuf.Int(bitbuf.U64, 0), bitbuf.Int(bitbuf.I64, 1), bitbuf.Int(bitbuf.I32, 7))
	if row, ok := st.Stats(dwcrypto.UserID([]byte("host")), 3); !ok || row.Rating != 1 || row.Values[0] != 7 {
		t.Fatalf("stats row %+v %v", row, ok)
	}

	// The session goes away with the host's connection.
	host.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.Lobby.Matchmaking.Open() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("session outlived its host connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
