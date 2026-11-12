package lobby

import (
	"context"
	"errors"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Profiles, lobby service 8 (LBYM 0x6ce08..0x6d240, lobby tasks 0x0e..0x14):
//
//	1 create(u8, i32, i32, blob[48])  2 read public(u8, u64 user)  3 read private(u8)
//	5 set private(u8, 4 x i32)        6 delete(u8)
//
// Public result (0x26960): u64 user, i32, i32, blob. Private result (0x26b18):
// u64 user, 4 x i32. Both players read their private profile after readying up.
const (
	profCreate      = 1
	profReadPublic  = 2
	profReadPrivate = 3
	profSetPrivate  = 5
	profDelete      = 6

	publicDataSize = 48
)

func (c *Conn) profiles(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 1 {
		c.log.Warn("profile task did not parse", "task", t.ID, "err", err)
		return Reply(t, 0, nil)
	}
	args := fields[1:]
	user := c.sess.UserID
	st := c.srv.Store

	switch t.ID {
	case profCreate:
		if len(args) >= 3 && args[2].Type == bitbuf.Blob {
			p := store.PublicProfile{A: int32(args[0].Int), B: int32(args[1].Int), Data: args[2].Bytes}
			if err := st.SetPublicProfile(ctx, user, p); err != nil {
				c.log.Error("save public profile", "err", err)
			}
		}
		return Reply(t, 0, nil)
	case profReadPublic:
		if len(args) < 1 {
			return Reply(t, 0, nil)
		}
		target := args[0].Int
		p, err := st.PublicProfile(ctx, target)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.log.Error("load public profile", "err", err)
		}
		if p.Data == nil {
			p.Data = make([]byte, publicDataSize)
		}
		return Reply(t, 1, []bitbuf.Field{bitbuf.Int(bitbuf.U64, target),
			bitbuf.Int(bitbuf.I32, uint64(uint32(p.A))), bitbuf.Int(bitbuf.I32, uint64(uint32(p.B))),
			bitbuf.Bytes(bitbuf.Blob, p.Data)})
	case profReadPrivate:
		p, err := st.PrivateProfile(ctx, user)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.log.Error("load private profile", "err", err)
		}
		out := []bitbuf.Field{bitbuf.Int(bitbuf.U64, user)}
		for _, v := range p {
			out = append(out, bitbuf.Int(bitbuf.I32, uint64(uint32(v))))
		}
		return Reply(t, 1, out)
	case profSetPrivate:
		var p store.PrivateProfile
		n := 0
		for _, f := range args {
			if f.Type == bitbuf.I32 && n < len(p) {
				p[n] = int32(f.Int)
				n++
			}
		}
		if n == len(p) {
			if err := st.SetPrivateProfile(ctx, user, p); err != nil {
				c.log.Error("save private profile", "err", err)
			}
			c.log.Info("private profile saved", "values", p)
		}
		return Reply(t, 0, nil)
	case profDelete:
		if err := st.DeleteProfile(ctx, user); err != nil {
			c.log.Error("delete profile", "err", err)
		}
		return Reply(t, 0, nil)
	}
	c.log.Info("profile task not implemented", "task", t.ID)
	return Reply(t, 0, nil)
}
