// Package lobby implements the lobby service gateway (bdLobbyService).
//
// The client opens with plain message 7 {u32 ticket.a, u32 ticket.seed, 1024-bit
// lobby ticket} and then sends tasks encrypted with the session key from its login
// ticket. A task's message type is its service; the typed payload starts with
// u8 slot, u8 seq, u8 task id. Server messages: 1 = task reply, 2 = push (one
// mailbox message, see mailbox.go).
//
// Task replies (docs/svr2007-services.md): u8 slot, u8 seq, u32 error, u8 task id
// (echoed; each service's parser only accepts its own result-bearing ids), then
// u32 count and results for tasks that return lists.
package lobby

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
	"github.com/princebyyourlogic/angelware/internal/frame"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
)

const (
	MsgHello     = 7
	msgTaskReply = 1
	msgPush      = 2
)

// Lobby services (task message types); see docs/svr2007-analysis.md.
const (
	svcStats       = 4
	svcMatchmaking = 5
	svcMailbox     = 6
	svcProfiles    = 8
	svcFriends     = 9
	svcStorage     = 10
	svcTitle       = 12
)

type Server struct {
	Store       store.Store
	Sessions    *session.Registry
	Matchmaking *Matchmaking
	Log         *slog.Logger

	mu      sync.Mutex
	online  map[uint64]*Conn     // user id -> gateway connection
	invites map[[2]uint64]invite // (inviter, invitee) -> join information
}

// Conn is one client's gateway connection.
type Conn struct {
	srv  *Server
	conn net.Conn
	log  *slog.Logger
	sess session.Session
	out  chan []byte // frames for the writer goroutine
	done chan struct{}
}

// outQueue bounds a client's unsent frames; a client that stops reading loses
// pushes (they stay in the mailbox) instead of blocking whoever notifies it.
const outQueue = 64

// Task is a decoded client task.
type Task struct {
	Service, Slot, Seq, ID uint8
	Args                   *bitbuf.Reader
}

// Serve runs a gateway connection that opened with hello.
func (s *Server) Serve(ctx context.Context, nc net.Conn, r *bufio.Reader, hello frame.Frame) {
	c := &Conn{srv: s, conn: nc, log: s.Log.With("peer", nc.RemoteAddr().String()),
		out: make(chan []byte, outQueue), done: make(chan struct{})}
	go c.writer()
	defer close(c.done)
	defer s.Matchmaking.DropOwner(c)
	if err := c.hello(hello); err != nil {
		c.log.Warn("gateway hello rejected", "err", err)
		return
	}
	s.setOnline(ctx, c)
	defer s.setOffline(ctx, c)
	for {
		f, err := frame.Read(r)
		if err != nil {
			c.log.Info("gateway closed", "err", err)
			return
		}
		if err := c.handle(ctx, f); err != nil {
			c.log.Warn("gateway frame dropped", "err", err)
		}
	}
}

func (c *Conn) hello(f frame.Frame) error {
	r, err := bitbuf.NewReader(f.Payload)
	if err != nil {
		return err
	}
	r.U32()
	r.U32()
	ticket, err := r.Raw(session.TicketSize)
	if err != nil {
		return err
	}
	sess, ok := c.srv.Sessions.Redeem(ticket)
	if !ok {
		return fmt.Errorf("unknown or expired ticket")
	}
	c.sess = sess
	c.log = c.log.With("user", fmt.Sprintf("%016x", sess.UserID), "name", sess.Name)
	c.log.Info("gateway connected")
	return nil
}

func (c *Conn) handle(ctx context.Context, f frame.Frame) error {
	if !f.Encrypted {
		c.log.Debug("plain gateway message ignored", "type", f.Type)
		return nil
	}
	plain, err := dwcrypto.Decrypt(c.sess.Key, dwcrypto.SeedIV(f.Seed), f.Payload)
	if err != nil {
		return err
	}
	service, payload, err := frame.Open(plain)
	if err != nil {
		return err
	}
	r, err := bitbuf.NewReader(payload)
	if err != nil {
		return err
	}
	t := Task{Service: service, Args: r}
	if t.Slot, err = r.U8(); err == nil {
		if t.Seq, err = r.U8(); err == nil {
			t.ID, err = r.U8()
		}
	}
	if err != nil {
		return fmt.Errorf("task header: %w", err)
	}
	c.log.Debug("task", "service", t.Service, "task", t.ID, "slot", t.Slot, "seq", t.Seq,
		"payload", fmt.Sprintf("%x", payload))

	ctx, cancel := context.WithTimeout(ctx, store.Timeout)
	defer cancel()
	var reply []byte
	switch t.Service {
	case svcMatchmaking:
		reply = c.srv.Matchmaking.Handle(c, t)
	case svcProfiles:
		reply = c.profiles(ctx, t)
	case svcStats:
		reply = c.stats(ctx, t)
	case svcMailbox:
		reply = c.mailbox(ctx, t)
	case svcFriends:
		reply = c.friends(ctx, t)
	case svcStorage:
		reply = c.storage(ctx, t)
	case svcTitle:
		reply = c.title(t)
	default:
		reply = Reply(t, nil)
	}
	return c.send(msgTaskReply, reply)
}

// send queues a frame, waiting for room (task replies must not be lost).
func (c *Conn) send(msgType uint8, payload []byte) error {
	select {
	case c.out <- frame.Plain(msgType, payload):
		return nil
	case <-c.done:
		return net.ErrClosed
	}
}

// trySend queues a frame only if there is room right away.
func (c *Conn) trySend(msgType uint8, payload []byte) bool {
	select {
	case c.out <- frame.Plain(msgType, payload):
		return true
	default:
		return false
	}
}

func (c *Conn) writer() {
	for {
		select {
		case b := <-c.out:
			if _, err := c.conn.Write(b); err != nil {
				c.conn.Close()
				return
			}
		case <-c.done:
			return
		}
	}
}

// Reply is a task result without a list: u32 error 0, u8 task id, then fields
// (a single result object, e.g. a profile).
func Reply(t Task, fields []bitbuf.Field) []byte {
	return bitbuf.NewWriter(true).U8(t.Slot).U8(t.Seq).U32(0).U8(t.ID).Fields(fields).Bytes()
}

// ErrorReply fails a task: the client reads the non-zero error and nothing after it.
func ErrorReply(t Task, code uint32) []byte {
	return bitbuf.NewWriter(true).U8(t.Slot).U8(t.Seq).U32(code).Bytes()
}

// ListReply is a task result carrying count items (fields holds all of them).
func ListReply(t Task, count uint32, fields []bitbuf.Field) []byte {
	return bitbuf.NewWriter(true).U8(t.Slot).U8(t.Seq).U32(0).U8(t.ID).U32(count).Fields(fields).Bytes()
}

// UserID is the connection's user.
func (c *Conn) UserID() uint64 { return c.sess.UserID }

// push sends one mailbox message to this client right away, without blocking.
func (c *Conn) push(m store.Message) {
	if !c.trySend(msgPush, pushPayload(m)) {
		c.log.Warn("push dropped: client queue full", "type", m.Type)
	}
}

func (s *Server) setOnline(ctx context.Context, c *Conn) {
	s.mu.Lock()
	if s.online == nil {
		s.online = map[uint64]*Conn{}
	}
	prev := s.online[c.sess.UserID]
	s.online[c.sess.UserID] = c
	s.mu.Unlock()
	if prev == nil {
		s.announce(ctx, c.sess, msgFriendOnline)
	}
}

func (s *Server) setOffline(ctx context.Context, c *Conn) {
	s.mu.Lock()
	gone := s.online[c.sess.UserID] == c
	if gone {
		delete(s.online, c.sess.UserID)
	}
	s.mu.Unlock()
	if gone {
		s.announce(context.WithoutCancel(ctx), c.sess, msgFriendOffline)
	}
}

// Online returns the gateway connection of a user, or nil.
func (s *Server) Online(user uint64) *Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online[user]
}
