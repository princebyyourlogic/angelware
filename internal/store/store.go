// Package store holds persistent data: accounts, profiles and stats.
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExists   = errors.New("store: already exists")
)

// Account is a DemonWare account. UserID is Tiger(name)[:8]; PasswordTiger is the
// Tiger hash the client sends at signup and uses as its login key. It is
// password-equivalent for this protocol, so treat the column as a secret.
type Account struct {
	UserID        uint64
	Name          string
	PasswordTiger []byte
}

// PublicProfile is what CreateProfile uploads (result layout LBYM 0x26960).
type PublicProfile struct {
	A, B int32
	Data []byte
}

// PrivateProfile is the per-player record (0x26b18); the game sets field 0 to 1
// before a match and back to 0 when it ends cleanly.
type PrivateProfile [4]int32

// StatsRow is one leaderboard write (lobby service 4, task 1).
type StatsRow struct {
	Board  int32
	Flag   uint8
	Rating int64
	Values []int32
}

type Store interface {
	CreateAccount(ctx context.Context, a Account) error
	Account(ctx context.Context, userID uint64) (Account, error)
	TouchLogin(ctx context.Context, userID uint64) error
	PublicProfile(ctx context.Context, userID uint64) (PublicProfile, error)
	SetPublicProfile(ctx context.Context, userID uint64, p PublicProfile) error
	PrivateProfile(ctx context.Context, userID uint64) (PrivateProfile, error)
	SetPrivateProfile(ctx context.Context, userID uint64, p PrivateProfile) error
	DeleteProfile(ctx context.Context, userID uint64) error
	WriteStats(ctx context.Context, userID uint64, row StatsRow) error
	DeleteStats(ctx context.Context, userID uint64, board int32) error
	Social
	Leaderboards
	Files
	Close()
}

// Memory is an in-process Store for tests and quick local runs.
type Memory struct {
	mu       sync.Mutex
	accounts map[uint64]Account
	public   map[uint64]PublicProfile
	private  map[uint64]PrivateProfile
	stats    map[[2]int64]StatsRow
	s        memSocial
	f        memFiles
}

func NewMemory() *Memory {
	return &Memory{accounts: map[uint64]Account{}, public: map[uint64]PublicProfile{},
		private: map[uint64]PrivateProfile{}, stats: map[[2]int64]StatsRow{}, s: newMemSocial()}
}

func (m *Memory) CreateAccount(_ context.Context, a Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[a.UserID]; ok {
		return ErrExists
	}
	m.accounts[a.UserID] = a
	return nil
}

func (m *Memory) Account(_ context.Context, id uint64) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return a, ErrNotFound
	}
	return a, nil
}

func (m *Memory) TouchLogin(context.Context, uint64) error { return nil }

func (m *Memory) PublicProfile(_ context.Context, id uint64) (PublicProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.public[id]
	if !ok {
		return p, ErrNotFound
	}
	return p, nil
}

func (m *Memory) SetPublicProfile(_ context.Context, id uint64, p PublicProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.public[id] = p
	return nil
}

func (m *Memory) PrivateProfile(_ context.Context, id uint64) (PrivateProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.private[id]
	if !ok {
		return p, ErrNotFound
	}
	return p, nil
}

func (m *Memory) SetPrivateProfile(_ context.Context, id uint64, p PrivateProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.private[id] = p
	return nil
}

func (m *Memory) DeleteProfile(_ context.Context, id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.public, id)
	delete(m.private, id)
	return nil
}

func (m *Memory) WriteStats(_ context.Context, id uint64, row StatsRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats[[2]int64{int64(id), int64(row.Board)}] = row
	return nil
}

func (m *Memory) DeleteStats(_ context.Context, id uint64, board int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.stats, [2]int64{int64(id), int64(board)})
	return nil
}

// Stats returns a stored row (tests).
func (m *Memory) Stats(id uint64, board int32) (StatsRow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.stats[[2]int64{int64(id), int64(board)}]
	return r, ok
}

func (m *Memory) Close() {}

// Timeout bounds every store call made while handling a client request.
const Timeout = 5 * time.Second
