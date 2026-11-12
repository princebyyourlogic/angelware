// Package lobby implements the lobby service gateway (bdLobbyService).
//
// The client opens with plain message 7 {u32 ticket.a, u32 ticket.seed, 1024-bit
// lobby ticket} and then sends tasks encrypted with the session key from its login
// ticket. A task's message type is its service; the typed payload starts with
// u8 slot, u8 seq, u8 task id. Server messages: 1 = task reply, 2 = push.
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
)

// Lobby services (task message types); see docs/svr2007-analysis.md.
const (
	svcStats       = 4
	svcMatchmaking = 5
	svcProfiles    = 8
)

type Server struct {
	Store       store.Store
	Sessions    *session.Registry
	Matchmaking *Matchmaking
	Log         *slog.Logger
}

// Conn is one client's gateway connection.
type Conn struct {
	srv  *Server
	conn net.Conn
	log  *slog.Logger
	sess session.Session
	wmu  sync.Mutex
}

// Task is a decoded client task.
type Task struct {
	Service, Slot, Seq, ID uint8
	Args                   *bitbuf.Reader
}

// Serve runs a gateway connection that opened with hello.
func (s *Server) Serve(ctx context.Context, nc net.Conn, r *bufio.Reader, hello frame.Frame) {
	c := &Conn{srv: s, conn: nc, log: s.Log.With("peer", nc.RemoteAddr().String())}
	defer s.Matchmaking.DropOwner(c)
	if err := c.hello(hello); err != nil {
		c.log.Warn("gateway hello rejected", "err", err)
		return
	}
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
	default:
		reply = Reply(t, 0, nil)
	}
	return c.send(msgTaskReply, reply)
}

func (c *Conn) send(msgType uint8, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(frame.Plain(msgType, payload))
	return err
}

// Reply is the generic task result (LBYM 0x6d308): u32 error, u8 count, fields.
func Reply(t Task, count uint8, fields []bitbuf.Field) []byte {
	return bitbuf.NewWriter(true).U8(t.Slot).U8(t.Seq).U32(0).U8(count).Fields(fields).Bytes()
}
