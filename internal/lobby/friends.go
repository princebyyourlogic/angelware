package lobby

import (
	"context"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Friends, lobby service 9 (senders LBYM 0x60a90..0x61920, lobby tasks 0x15..0x21):
//
//	1  ProposeFriend(u8, u64 user[, blob, u32])        -> message 1 to them
//	   (ignored between friends; repeats are not re-sent; if they already asked
//	   us, it accepts their request instead)
//	13 WithdrawProposalFriend(u8, u64 user)             -> message 4
//	2  AcceptProposeFriend(u8, u64 user)                -> message 2
//	3  RejectProposeFriend(u8, u64 user)                -> message 3
//	4  RemoveFriend(u8, u64 user)
//	19 LoadFriendProposeList(u8)  -> u64 user, string name
//	5  LoadFriendList(u8)         -> u64 user, string name, bool online
//	6  SetBlockUser(u8, u64 user, u8 level)
//	7  LoadBlockUserList(u8)      -> u64 user, string name, u8 level
//	12 SendFriendMessage(u8, u64 user, ..., blob text, ...)        -> message 8
//	8  InviteGameSession(u8, u64 user, blob session id[8])         -> message 5
//	9  AcceptInvitation(u8, u64 user) / 10 RejectInvitation        -> message 6 / 7
//
// Captured from the retail game: ProposeFriend carried only u8 + u64, and an invite
// u8 + u64 + the hosted session's 8-byte id (which the invitee then looks up with
// matchmaking task 4).
//
// Friendships, requests and blocks persist; every notification goes through the
// mailbox so a player who is offline sees it at their next login.
const (
	frPropose  = 1
	frAccept   = 2
	frReject   = 3
	frRemove   = 4
	frList     = 5
	frBlock    = 6
	frBlocks   = 7
	frInvite   = 8
	frInviteOK = 9
	frInviteNo = 10
	frMessage  = 12
	frWithdraw = 13
	frRequests = 19
)

// invite remembers the session of a sent invite so the answer can carry it back
// to the inviter.
type invite struct {
	session []byte
}

// firstBlob returns the first blob among a task's arguments.
func firstBlob(args []bitbuf.Field) []byte {
	for _, f := range args {
		if f.Type == bitbuf.Blob {
			return f.Bytes
		}
	}
	return nil
}

func (c *Conn) friends(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 1 {
		c.log.Warn("friends task did not parse", "task", t.ID, "err", err)
		return Reply(t, nil)
	}
	args := fields[1:]
	st, me := c.srv.Store, c.sess.UserID

	// Tasks that name another player carry their id first.
	var other uint64
	if len(args) > 0 && args[0].Type == bitbuf.U64 {
		other = args[0].Int
	}
	note := func(to uint64, typ uint32) store.Message {
		return store.Message{To: to, Type: typ, From: me, FromName: c.sess.Name}
	}
	fail := func(what string, err error) {
		if err != nil {
			c.log.Error(what, "err", err)
		}
	}

	switch t.ID {
	case frPropose:
		if other == 0 || other == me {
			return Reply(t, nil)
		}
		if blocked, _ := st.IsBlocked(ctx, other, me); blocked {
			c.log.Info("friend request to a player who blocked us dropped")
			return Reply(t, nil)
		}
		if already, err := st.AreFriends(ctx, me, other); already || err != nil {
			fail("check friendship", err)
			c.log.Info("friend request between existing friends ignored")
			return Reply(t, nil)
		}
		// They already asked us: treat our request as accepting theirs.
		if crossed, err := st.RemoveFriendRequest(ctx, other, me); crossed {
			fail("save friendship", st.AddFriendship(ctx, me, other))
			c.srv.Notify(ctx, note(other, msgFriendAccepted))
			c.log.Info("crossed friend requests: now friends")
			return Reply(t, nil)
		} else {
			fail("check reverse request", err)
		}
		m := note(other, msgFriendRequest)
		m.Data = firstBlob(args)
		created, err := st.AddFriendRequest(ctx, me, other, m.Data)
		fail("save friend request", err)
		if created {
			c.srv.Notify(ctx, m)
		} else {
			c.log.Info("repeated friend request not sent again")
		}
	case frWithdraw:
		if ok, err := st.RemoveFriendRequest(ctx, me, other); ok {
			c.srv.Notify(ctx, note(other, msgFriendCanceled))
		} else {
			fail("withdraw friend request", err)
		}
	case frAccept:
		ok, err := st.RemoveFriendRequest(ctx, other, me)
		fail("accept friend request", err)
		if ok {
			fail("save friendship", st.AddFriendship(ctx, me, other))
			c.srv.Notify(ctx, note(other, msgFriendAccepted))
		}
	case frReject:
		if ok, err := st.RemoveFriendRequest(ctx, other, me); ok {
			c.srv.Notify(ctx, note(other, msgFriendRejected))
		} else {
			fail("reject friend request", err)
		}
	case frRemove:
		fail("remove friend", st.RemoveFriendship(ctx, me, other))
	case frRequests:
		list, err := st.FriendRequestsTo(ctx, me)
		fail("load friend requests", err)
		var out []bitbuf.Field
		for _, f := range list {
			out = append(out, bitbuf.Int(bitbuf.U64, f.UserID), bitbuf.Bytes(bitbuf.String, []byte(f.Name)))
		}
		return ListReply(t, uint32(len(list)), out)
	case frList:
		list, err := st.Friends(ctx, me)
		fail("load friends", err)
		var out []bitbuf.Field
		for _, f := range list {
			var online uint64
			if c.srv.Online(f.UserID) != nil {
				online = 1
			}
			out = append(out, bitbuf.Int(bitbuf.U64, f.UserID), bitbuf.Bytes(bitbuf.String, []byte(f.Name)),
				bitbuf.Int(bitbuf.Bool, online))
		}
		return ListReply(t, uint32(len(list)), out)
	case frBlock:
		if len(args) >= 2 && other != 0 {
			fail("save block", st.SetBlock(ctx, me, other, uint8(args[1].Int)))
		}
	case frBlocks:
		list, err := st.Blocks(ctx, me)
		fail("load blocks", err)
		var out []bitbuf.Field
		for _, f := range list {
			out = append(out, bitbuf.Int(bitbuf.U64, f.UserID), bitbuf.Bytes(bitbuf.String, []byte(f.Name)),
				bitbuf.Int(bitbuf.U8, uint64(f.Level)))
		}
		return ListReply(t, uint32(len(list)), out)
	case frMessage:
		if blocked, _ := st.IsBlocked(ctx, other, me); blocked || other == 0 {
			return Reply(t, nil)
		}
		m := note(other, msgFriendMessage)
		m.Data = firstBlob(args)
		c.srv.Notify(ctx, m)
	case frInvite:
		if blocked, _ := st.IsBlocked(ctx, other, me); blocked || other == 0 {
			return Reply(t, nil)
		}
		inv := invite{session: firstBlob(args)}
		c.srv.setInvite(me, other, inv)
		m := note(other, msgInvite)
		m.Data = inv.session
		c.srv.Notify(ctx, m)
	case frInviteOK, frInviteNo:
		inv := c.srv.takeInvite(other, me)
		typ := uint32(msgInviteAccepted)
		if t.ID == frInviteNo {
			typ = msgInviteRejected
		}
		m := note(other, typ)
		m.Data = inv.session
		c.srv.Notify(ctx, m)
	default:
		c.log.Info("friends task not implemented", "task", t.ID, "args", fields)
		if t.ID == 16 || t.ID == 17 {
			return ListReply(t, 0, nil)
		}
	}
	return Reply(t, nil)
}

func (s *Server) setInvite(from, to uint64, inv invite) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invites == nil {
		s.invites = map[[2]uint64]invite{}
	}
	s.invites[[2]uint64{from, to}] = inv
}

func (s *Server) takeInvite(from, to uint64) invite {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv := s.invites[[2]uint64{from, to}]
	delete(s.invites, [2]uint64{from, to})
	return inv
}
