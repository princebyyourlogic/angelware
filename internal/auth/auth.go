// Package auth implements bdAuthService (TCP, one connection per request).
//
// Requests use even message types; replies use type+1 and start with u32 status
// (700 = OK). Every request begins with u32 seed, u32 title id.
//
//	0x00 CreateAccount: 64-bit id (0), 0x60-byte block {u32 0xDEADBDEF, name[64],
//	     Tiger(password)}, 3DES-CBC with the fixed key DEADBEEF x4 + 8 zero bytes.
//	0x0A AuthAccount: 64-bit id = Tiger(name)[:8], nothing encrypted.
//
// Login replies carry a 0x80-byte ticket block (magic, ids, name, session key) and
// an opaque 0x80-byte lobby ticket. Reply 0x0B encrypts the block with the
// account's Tiger(password) (the client decrypts it with its own copy and checks the
// magic), so only the account holder can use it. Reply 0x11 sends the block in the
// clear; the client accepts it for any request (verified in PCSX2, 2026-11-11).
package auth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
	"github.com/princebyyourlogic/angelware/internal/frame"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
)

const (
	TitleID = 4669

	statusOK = 700
	// Any status other than 700 fails the request on the client. The DemonWare
	// error numbering for these cases is not known, so one value is used.
	statusFailed = 701

	reqCreateAccount = 0x00
	reqAuthAccount   = 0x0A
	replyTicketKeyed = 0x0B
	replyTicketPlain = 0x11
)

var (
	ticketMagic = []byte{0xde, 0xad, 0xbd, 0xef}
	signupKey   = append(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 4), make([]byte, 8)...)
)

// Mode selects how logins are answered.
type Mode string

const (
	// Verify requires a registered account and answers with the keyed 0x0B reply.
	Verify Mode = "verify"
	// Open accepts any login with the plaintext 0x11 reply (no password check).
	Open Mode = "open"
)

type Service struct {
	Store    store.Store
	Sessions *session.Registry
	Mode     Mode
	Log      *slog.Logger
}

// Serve answers requests on one auth connection, starting with first.
func (s *Service) Serve(ctx context.Context, conn net.Conn, r *bufio.Reader, first frame.Frame) {
	log := s.Log.With("peer", conn.RemoteAddr().String())
	for f := first; ; {
		if reply, err := s.handle(ctx, log, f); err != nil {
			log.Warn("auth request failed", "type", f.Type, "err", err)
			return
		} else if _, err := conn.Write(reply); err != nil {
			return
		}
		var err error
		if f, err = frame.Read(r); err != nil {
			return
		}
	}
}

func (s *Service) handle(ctx context.Context, log *slog.Logger, f frame.Frame) ([]byte, error) {
	if f.Encrypted {
		return nil, errors.New("encrypted auth request")
	}
	r, err := bitbuf.NewReader(f.Payload)
	if err != nil {
		return nil, err
	}
	seed, _ := r.U32()
	title, err := r.U32()
	if err != nil {
		return nil, err
	}
	if title != TitleID {
		log.Warn("unexpected title id", "title", title)
	}
	ctx, cancel := context.WithTimeout(ctx, store.Timeout)
	defer cancel()

	switch f.Type {
	case reqCreateAccount:
		return s.createAccount(ctx, log, seed, r)
	case reqAuthAccount:
		raw, err := r.Raw(8)
		if err != nil {
			return nil, err
		}
		return s.login(ctx, log, binary.LittleEndian.Uint64(raw))
	default:
		log.Info("auth request not implemented, answering OK", "type", f.Type, "seed", seed)
		return status(f.Type+1, statusOK), nil
	}
}

func (s *Service) createAccount(ctx context.Context, log *slog.Logger, seed uint32, r *bitbuf.Reader) ([]byte, error) {
	reply := func(code uint32) ([]byte, error) { return status(reqCreateAccount+1, code), nil }
	r.Raw(8) // id, zero at signup
	enc, err := r.Raw(0x60)
	if err != nil {
		return nil, err
	}
	block, err := dwcrypto.Decrypt(signupKey, dwcrypto.SeedIV(seed), enc)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(block[:4], ticketMagic) {
		log.Warn("signup block did not decrypt")
		return reply(statusFailed)
	}
	name := block[4:68]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	if len(name) == 0 {
		return reply(statusFailed)
	}
	acct := store.Account{UserID: dwcrypto.UserID(name), Name: string(name),
		PasswordTiger: bytes.Clone(block[68:92])}
	switch err := s.Store.CreateAccount(ctx, acct); {
	case errors.Is(err, store.ErrExists):
		log.Info("signup for existing name", "name", acct.Name)
		return reply(statusFailed)
	case err != nil:
		return nil, err
	}
	log.Info("account created", "name", acct.Name, "user", fmt.Sprintf("%016x", acct.UserID))
	return reply(statusOK)
}

func status(msgType uint8, code uint32) []byte {
	return frame.Plain(msgType, bitbuf.NewWriter(false).U32(code).Bytes())
}

func (s *Service) login(ctx context.Context, log *slog.Logger, userID uint64) ([]byte, error) {
	name := ""
	var key []byte
	acct, err := s.Store.Account(ctx, userID)
	switch {
	case err == nil:
		name, key = acct.Name, acct.PasswordTiger
	case errors.Is(err, store.ErrNotFound) && s.Mode == Open:
	case errors.Is(err, store.ErrNotFound):
		log.Info("login for unknown account", "user", fmt.Sprintf("%016x", userID))
		return status(replyTicketKeyed, statusFailed), nil
	default:
		return nil, err
	}

	sess, ticket := s.Sessions.Issue(userID, name)
	block := ticketBlock(userID, name, sess.Key)
	w := bitbuf.NewWriter(false).U32(statusOK)
	msgType := uint8(replyTicketPlain)
	if s.Mode == Verify {
		var seed [4]byte
		rand.Read(seed[:])
		enc, err := dwcrypto.Encrypt(key, dwcrypto.SeedIV(binary.LittleEndian.Uint32(seed[:])), block)
		if err != nil {
			return nil, err
		}
		w.U32(binary.LittleEndian.Uint32(seed[:]))
		block, msgType = enc, replyTicketKeyed
	} else {
		w.U32(0)
	}
	if name != "" {
		if err := s.Store.TouchLogin(ctx, userID); err != nil {
			log.Warn("record login time", "err", err)
		}
	}
	log.Info("login", "user", fmt.Sprintf("%016x", userID), "name", name, "mode", s.Mode)
	return frame.Plain(msgType, w.Raw(block).Raw(ticket).Bytes()), nil
}

// ticketBlock builds the 0x80-byte block parsed at LBYM 0x75020, packed without
// padding: magic, u8, u32 (kept by the client and echoed to the gateway), u32
// title, u32, u64, u64, name[64], session key[24].
func ticketBlock(userID uint64, name string, key []byte) []byte {
	b := make([]byte, 0, 0x80)
	b = append(b, ticketMagic...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(userID))
	b = binary.LittleEndian.AppendUint32(b, TitleID)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint64(b, userID)
	b = binary.LittleEndian.AppendUint64(b, userID)
	var n [64]byte
	copy(n[:63], name)
	b = append(b, n[:]...)
	b = append(b, key...)
	return append(b, make([]byte, 0x80-len(b))...)
}
