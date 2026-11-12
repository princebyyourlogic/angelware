// Package session issues the lobby tickets handed out at login and redeemed when
// the client opens the lobby service gateway.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

const (
	TicketSize = 0x80 // the client forwards these 1024 bits verbatim
	KeySize    = 24   // 3DES session key for lobby traffic
	ttl        = 15 * time.Minute
)

var ticketMagic = [4]byte{'A', 'N', 'G', 'L'}

type Session struct {
	UserID  uint64
	Name    string
	Key     []byte
	expires time.Time
}

type Registry struct {
	mu       sync.Mutex
	sessions map[[16]byte]Session
}

func NewRegistry() *Registry { return &Registry{sessions: map[[16]byte]Session{}} }

// Issue creates a session and returns its opaque lobby ticket.
func (r *Registry) Issue(userID uint64, name string) (Session, []byte) {
	var token [16]byte
	rand.Read(token[:])
	s := Session{UserID: userID, Name: name, Key: make([]byte, KeySize), expires: time.Now().Add(ttl)}
	rand.Read(s.Key)

	ticket := make([]byte, TicketSize)
	copy(ticket, ticketMagic[:])
	copy(ticket[4:], token[:])
	binary.LittleEndian.PutUint64(ticket[20:], userID)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, v := range r.sessions {
		if now.After(v.expires) {
			delete(r.sessions, k)
		}
	}
	r.sessions[token] = s
	return s, ticket
}

// Redeem looks up the session for a ticket. Tickets stay valid until they expire so
// a client can reconnect to the gateway after a dropped connection.
func (r *Registry) Redeem(ticket []byte) (Session, bool) {
	if len(ticket) < 20 || [4]byte(ticket[:4]) != ticketMagic {
		return Session{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[[16]byte(ticket[4:20])]
	if !ok || time.Now().After(s.expires) {
		return Session{}, false
	}
	return s, true
}
