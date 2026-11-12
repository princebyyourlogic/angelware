package lobby

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Mailbox, lobby service 6 (senders LBYM 0x69d68..0x6a198, lobby tasks 0x2c..0x2f).
// The game polls about once a second, hands each message to its lobby callback
// and then acknowledges it, so stored messages survive until the recipient's game
// has really seen them, including across logins.
//
//	1 fetch(u8, u32 offset, u32 count, bool, bool)  -> u32 count, messages
//	4 ack(u8, u64 message id)
//	5 fetch variant (as 1)
//	6 mark(u8, u64 message id, bool)
//
// A message (decoder 0x6a8e8, classes 0x76f08/0x6ca70/0x6bb60/0x6b7b8/0x6b4a0):
//
//	u32 type; u64 timestamp; u64 message id; u32 0; bool 0
//	u64 from user; string from name
//	type 1:     u16, blob             (friend request)
//	types 5-7:  blob, u16, blob       (invite and its answers: join information)
//	types 8-12: blob                  (friend message text, online/offline, block)
//
// A push (gateway message 2) carries one message in the same encoding; the game
// dedupes by message id.
const (
	mbFetch    = 1
	mbAck      = 4
	mbFetch2   = 5
	mbMark     = 6
	mbMaxFetch = 50

	msgFriendRequest  = 1
	msgFriendAccepted = 2
	msgFriendRejected = 3
	msgFriendCanceled = 4
	msgInvite         = 5
	msgInviteAccepted = 6
	msgInviteRejected = 7
	msgFriendMessage  = 8
	msgFriendOnline   = 9
	msgFriendOffline  = 10
)

func messageFields(m store.Message) []bitbuf.Field {
	f := []bitbuf.Field{
		bitbuf.Int(bitbuf.U32, uint64(m.Type)),
		bitbuf.Int(bitbuf.U64, uint64(m.Created.Unix())),
		bitbuf.Int(bitbuf.U64, m.ID),
		bitbuf.Int(bitbuf.U32, 0),
		bitbuf.Int(bitbuf.Bool, 0),
		bitbuf.Int(bitbuf.U64, m.From),
		bitbuf.Bytes(bitbuf.String, []byte(truncate(m.FromName, 63))),
	}
	data, data2 := orEmpty(m.Data), orEmpty(m.Data2)
	switch {
	case m.Type == msgFriendRequest:
		f = append(f, bitbuf.Int(bitbuf.U16, uint64(m.Small)), bitbuf.Bytes(bitbuf.Blob, data))
	case m.Type >= msgInvite && m.Type <= msgInviteRejected:
		f = append(f, bitbuf.Bytes(bitbuf.Blob, data), bitbuf.Int(bitbuf.U16, uint64(m.Small)),
			bitbuf.Bytes(bitbuf.Blob, data2))
	case m.Type >= msgFriendMessage:
		f = append(f, bitbuf.Bytes(bitbuf.Blob, data))
	}
	return f
}

// pushPayload is a gateway message 2: one typed message, no envelope (0x6ad48).
func pushPayload(m store.Message) []byte {
	return bitbuf.NewWriter(true).Fields(messageFields(m)).Bytes()
}

var timeNow = time.Now

func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (c *Conn) mailbox(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 1 {
		c.log.Warn("mailbox task did not parse", "task", t.ID, "err", err)
		return Reply(t, nil)
	}
	args := fields[1:]
	switch t.ID {
	case mbFetch, mbFetch2:
		offset, limit := 0, 20
		if len(args) >= 2 {
			offset, limit = int(args[0].Int), int(args[1].Int)
		}
		limit = min(max(limit, 0), mbMaxFetch)
		msgs, err := c.srv.Store.Inbox(ctx, c.sess.UserID, offset, limit)
		if err != nil {
			c.log.Error("load mailbox", "err", err)
		}
		var out []bitbuf.Field
		for _, m := range msgs {
			out = append(out, messageFields(m)...)
		}
		if len(msgs) > 0 {
			c.log.Info("mailbox delivered", "messages", len(msgs))
		}
		return ListReply(t, uint32(len(msgs)), out)
	case mbAck:
		if len(args) >= 1 {
			if err := c.srv.Store.Ack(ctx, c.sess.UserID, args[0].Int); err != nil {
				c.log.Error("ack message", "err", err)
			}
		}
		return Reply(t, nil)
	case mbMark:
		return Reply(t, nil)
	}
	c.log.Info("mailbox task not implemented", "task", t.ID)
	return Reply(t, nil)
}

// Notify stores a message for its recipient and pushes it if they are online.
func (s *Server) Notify(ctx context.Context, m store.Message) {
	id, err := s.Store.Enqueue(ctx, m)
	if err != nil {
		s.Log.Error("queue message", "err", err, "type", m.Type, "to", fmt.Sprintf("%016x", m.To))
		return
	}
	m.ID = id
	if c := s.Online(m.To); c != nil {
		m.Created = timeNow()
		c.push(m)
	}
	s.Log.Info("message queued", "type", m.Type, "from", fmt.Sprintf("%016x", m.From),
		"to", fmt.Sprintf("%016x", m.To), "online", s.Online(m.To) != nil)
}

// announce pushes a presence change to the user's online friends. Presence is not
// stored: a friend who is offline now has no use for it later.
func (s *Server) announce(ctx context.Context, sess session.Session, msgType uint32) {
	friends, err := s.Store.Friends(ctx, sess.UserID)
	if err != nil {
		s.Log.Error("load friends for presence", "err", err)
		return
	}
	for _, f := range friends {
		if c := s.Online(f.UserID); c != nil {
			c.push(store.Message{ID: ephemeralID(), To: f.UserID, Type: msgType, From: sess.UserID,
				FromName: sess.Name, Created: timeNow()})
		}
	}
}

// ephemeralID gives push-only messages an id that cannot collide with stored
// ones (which count up from 1); acknowledging it is a no-op.
func ephemeralID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:]) | 1<<63
}
