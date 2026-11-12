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

// client plays the console's side of one TCP connection. A reader goroutine
// sorts incoming frames into replies and pushes (gateway message 2).
type client struct {
	t       *testing.T
	conn    net.Conn
	replies chan frame.Frame
	pushes  chan frame.Frame
	key     []byte
	seed    uint32
}

func dial(t *testing.T, s *TCP) *client {
	a, b := net.Pipe()
	go s.handle(context.Background(), b)
	t.Cleanup(func() { a.Close() })
	c := &client{t: t, conn: a, replies: make(chan frame.Frame, 16), pushes: make(chan frame.Frame, 16)}
	go func() {
		r := bufio.NewReader(a)
		for {
			f, err := frame.Read(r)
			if err != nil {
				close(c.replies)
				return
			}
			if !f.Encrypted && f.Type == 2 {
				c.pushes <- f
			} else {
				c.replies <- f
			}
		}
	}()
	return c
}

func (c *client) roundTrip(out []byte) frame.Frame {
	c.t.Helper()
	if _, err := c.conn.Write(out); err != nil {
		c.t.Fatal(err)
	}
	select {
	case f, ok := <-c.replies:
		if !ok {
			c.t.Fatal("connection closed")
		}
		return f
	case <-time.After(2 * time.Second):
		c.t.Fatal("no reply")
	}
	return frame.Frame{}
}

// push waits for the next pushed mailbox message and returns its fields.
func (c *client) push() []bitbuf.Field {
	c.t.Helper()
	select {
	case f := <-c.pushes:
		r, _ := bitbuf.NewReader(f.Payload)
		fs, err := r.Fields()
		if err != nil {
			c.t.Fatal(err)
		}
		return fs
	case <-time.After(2 * time.Second):
		c.t.Fatal("no push")
	}
	return nil
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
	if code, _ := r.U32(); code != 0 {
		c.t.Fatalf("reply error %d", code)
	}
	if echoed, _ := r.U8(); echoed != id {
		c.t.Fatalf("reply echoes task %d, want %d", echoed, id)
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
	if n, _ := r.U32(); n != 1 {
		t.Fatalf("create count %d", n)
	}
	id, _ := r.Field()

	// The guest's search returns the stored info with the assigned id.
	r = guest.task(5, 2, 5, bitbuf.Int(bitbuf.U8, 0), bitbuf.Int(bitbuf.I32, 1))
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

func u8(v uint64) bitbuf.Field  { return bitbuf.Int(bitbuf.U8, v) }
func u64(v uint64) bitbuf.Field { return bitbuf.Int(bitbuf.U64, v) }

// fetch reads the mailbox (service 6 task 1) and returns each message's fields.
func (c *client) fetch(slot uint8) [][]bitbuf.Field {
	c.t.Helper()
	r := c.task(6, slot, 1, u8(0), bitbuf.Int(bitbuf.U32, 0), bitbuf.Int(bitbuf.U32, 20),
		bitbuf.Int(bitbuf.Bool, 1), bitbuf.Int(bitbuf.Bool, 1))
	n, _ := r.U32()
	all, err := r.Fields()
	if err != nil {
		c.t.Fatal(err)
	}
	var msgs [][]bitbuf.Field
	for i := 0; i < int(n); i++ {
		// header (5) + sender (2), then per type; a u16 length of 0 has no blob after it.
		size := 7
		switch t := all[0].Int; {
		case t == 1:
			size = 8
			if all[7].Int > 0 {
				size = 9
			}
		case t >= 5 && t <= 7:
			size = 9
			if all[8].Int > 0 {
				size = 10
			}
		case t >= 8:
			size = 8
		}
		msgs = append(msgs, all[:size])
		all = all[size:]
	}
	return msgs
}

func TestFriendsMailboxAndPresence(t *testing.T) {
	s, _ := newTCP(auth.Verify)
	for _, n := range []string{"host", "guest"} {
		dial(t, s).roundTrip(signup(n, n+"pw"))
	}
	hostID, guestID := dwcrypto.UserID([]byte("host")), dwcrypto.UserID([]byte("guest"))
	host := loginAndOpenGateway(t, s, "host", "hostpw")

	// The guest is offline: the requests wait in their mailbox. The first is how the
	// retail game sends it (no data); a second request from another player with
	// data checks that messages in one fetch stay aligned.
	host.task(9, 1, 1, u8(0), u64(guestID))
	dial(t, s).roundTrip(signup("third", "thirdpw"))
	third := loginAndOpenGateway(t, s, "third", "thirdpw")
	third.task(9, 1, 1, u8(0), u64(guestID), bitbuf.Bytes(bitbuf.Blob, []byte("hi")), bitbuf.Int(bitbuf.U32, 2))

	guest := loginAndOpenGateway(t, s, "guest", "guestpw")
	msgs := guest.fetch(2)
	if len(msgs) != 2 || msgs[0][0].Int != 1 || msgs[0][5].Int != hostID || string(msgs[0][6].Bytes) != "host" ||
		msgs[0][7].Int != 0 || len(msgs[0]) != 8 ||
		msgs[1][7].Int != 2 || string(msgs[1][8].Bytes) != "hi" {
		t.Fatalf("mailbox %v", msgs)
	}
	r := guest.task(9, 3, 19, u8(0)) // pending requests list
	if n, _ := r.U32(); n != 2 {
		t.Fatalf("requests %d", n)
	}
	guest.task(6, 4, 4, u8(0), u64(msgs[0][2].Int)) // acknowledge both
	guest.task(6, 4, 4, u8(0), u64(msgs[1][2].Int))
	if left := guest.fetch(5); len(left) != 0 {
		t.Fatalf("message not removed after ack: %v", left)
	}

	// Accepting reaches the host live; both now list each other as online friends.
	guest.task(9, 6, 2, u8(0), u64(hostID))
	if m := host.push(); m[0].Int != 2 || m[5].Int != guestID {
		t.Fatalf("accept push %v", m)
	}
	r = host.task(9, 7, 5, u8(0))
	n, _ := r.U32()
	friends, _ := r.Fields()
	if n != 1 || friends[0].Int != guestID || string(friends[1].Bytes) != "guest" || friends[2].Int != 1 {
		t.Fatalf("friend list %d %v", n, friends)
	}

	// Already friends: a request back is ignored, nothing reaches the host.
	guest.task(9, 11, 1, u8(0), u64(hostID))
	select {
	case f := <-host.pushes:
		t.Fatalf("request between friends was delivered: %x", f.Payload)
	case <-time.After(100 * time.Millisecond):
	}

	// Friend message and an invite with its join information, answered.
	host.task(9, 8, 12, u8(0), u64(guestID), bitbuf.Int(bitbuf.U32, 4),
		bitbuf.Bytes(bitbuf.Blob, []byte("gg")), bitbuf.Int(bitbuf.U32, 0))
	if m := guest.push(); m[0].Int != 8 || string(m[7].Bytes) != "gg" {
		t.Fatalf("message push %v", m)
	}
	// Invite as the retail game sends it: u8, u64 friend, blob session id.
	sid := []byte{0x1d, 0x18, 0x44, 0x06, 0xc5, 0x37, 0x43, 0xa7}
	host.task(9, 9, 8, u8(0), u64(guestID), bitbuf.Bytes(bitbuf.Blob, sid))
	if m := guest.push(); m[0].Int != 5 || !bytes.Equal(m[7].Bytes, sid) || m[8].Int != 0 || len(m) != 9 {
		t.Fatalf("invite push %v", m)
	}
	guest.task(9, 10, 9, u8(0), u64(hostID))
	if m := host.push(); m[0].Int != 6 || !bytes.Equal(m[7].Bytes, sid) {
		t.Fatalf("invite accept push %v", m)
	}

	// Presence: the guest reconnecting is announced to the online host.
	guest.conn.Close()
	if m := host.push(); m[0].Int != 10 {
		t.Fatalf("offline push %v", m)
	}
	loginAndOpenGateway(t, s, "guest", "guestpw")
	if m := host.push(); m[0].Int != 9 || m[5].Int != guestID {
		t.Fatalf("online push %v", m)
	}
}

func TestRepeatedAndCrossedFriendRequests(t *testing.T) {
	s, st := newTCP(auth.Verify)
	for _, n := range []string{"ann", "bob"} {
		dial(t, s).roundTrip(signup(n, n+"pw"))
	}
	annID, bobID := dwcrypto.UserID([]byte("ann")), dwcrypto.UserID([]byte("bob"))
	ann := loginAndOpenGateway(t, s, "ann", "annpw")
	bob := loginAndOpenGateway(t, s, "bob", "bobpw")
	bob.task(9, 1, 1, u8(0), u64(annID))
	ann.push()                           // the request
	bob.task(9, 2, 1, u8(0), u64(annID)) // repeat: not delivered twice
	select {
	case <-ann.pushes:
		t.Fatal("repeated request delivered again")
	case <-time.After(100 * time.Millisecond):
	}
	// Ann asks Bob back instead of accepting: that makes them friends.
	ann.task(9, 3, 1, u8(0), u64(bobID))
	if m := bob.push(); m[0].Int != 2 || m[5].Int != annID {
		t.Fatalf("crossed request should accept: %v", m)
	}
	if ok, _ := st.AreFriends(context.Background(), annID, bobID); !ok {
		t.Fatal("not friends after crossed requests")
	}
	if reqs, _ := st.FriendRequestsTo(context.Background(), annID); len(reqs) != 0 {
		t.Fatalf("request left behind: %v", reqs)
	}
}
