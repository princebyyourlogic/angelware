package store

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Message is a stored mailbox notification (lobby service 6), kept until the
// recipient's game acknowledges it, so offline players get it at their next login.
type Message struct {
	ID       uint64
	To       uint64
	Type     uint32 // 1 friend request ... 8 friend message; see lobby/mailbox.go
	From     uint64
	FromName string
	Small    uint16 // the u16 some message types carry
	Data     []byte // first blob
	Data2    []byte // second blob (invites)
	Created  time.Time
}

// Contact is one entry of a friend, request or block list.
type Contact struct {
	UserID uint64
	Name   string
	Level  uint8 // block level (blocks only)
}

// Social is the persistent part of friends, blocks and the mailbox.
type Social interface {
	Enqueue(ctx context.Context, m Message) (uint64, error)
	Inbox(ctx context.Context, user uint64, offset, limit int) ([]Message, error)
	Ack(ctx context.Context, user, messageID uint64) error

	AddFriendRequest(ctx context.Context, from, to uint64, data []byte) error
	// RemoveFriendRequest reports whether a request existed.
	RemoveFriendRequest(ctx context.Context, from, to uint64) (bool, error)
	FriendRequestsTo(ctx context.Context, to uint64) ([]Contact, error)
	AddFriendship(ctx context.Context, a, b uint64) error
	RemoveFriendship(ctx context.Context, a, b uint64) error
	Friends(ctx context.Context, user uint64) ([]Contact, error)
	SetBlock(ctx context.Context, user, target uint64, level uint8) error
	Blocks(ctx context.Context, user uint64) ([]Contact, error)
	IsBlocked(ctx context.Context, user, target uint64) (bool, error)
}

// --- in-memory -------------------------------------------------------------

type memSocial struct {
	mu       sync.Mutex
	nextID   uint64
	mail     map[uint64]Message
	requests map[[2]uint64][]byte // (from, to) -> data
	friends  map[[2]uint64]bool   // both directions
	blocks   map[[2]uint64]uint8
}

func newMemSocial() memSocial {
	return memSocial{mail: map[uint64]Message{}, requests: map[[2]uint64][]byte{},
		friends: map[[2]uint64]bool{}, blocks: map[[2]uint64]uint8{}}
}

func (m *Memory) Enqueue(_ context.Context, msg Message) (uint64, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	m.s.nextID++
	msg.ID, msg.Created = m.s.nextID, time.Now()
	m.s.mail[msg.ID] = msg
	return msg.ID, nil
}

func (m *Memory) Inbox(_ context.Context, user uint64, offset, limit int) ([]Message, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	var out []Message
	for _, msg := range m.s.mail {
		if msg.To == user {
			out = append(out, msg)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) Ack(_ context.Context, user, id uint64) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if msg, ok := m.s.mail[id]; ok && msg.To == user {
		delete(m.s.mail, id)
	}
	return nil
}

func (m *Memory) AddFriendRequest(_ context.Context, from, to uint64, data []byte) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	m.s.requests[[2]uint64{from, to}] = data
	return nil
}

func (m *Memory) RemoveFriendRequest(_ context.Context, from, to uint64) (bool, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	_, ok := m.s.requests[[2]uint64{from, to}]
	delete(m.s.requests, [2]uint64{from, to})
	return ok, nil
}

func (m *Memory) FriendRequestsTo(_ context.Context, to uint64) ([]Contact, error) {
	m.s.mu.Lock()
	var ids []uint64
	for k := range m.s.requests {
		if k[1] == to {
			ids = append(ids, k[0])
		}
	}
	m.s.mu.Unlock()
	return m.contacts(ids, nil), nil
}

func (m *Memory) AddFriendship(_ context.Context, a, b uint64) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	m.s.friends[[2]uint64{a, b}], m.s.friends[[2]uint64{b, a}] = true, true
	return nil
}

func (m *Memory) RemoveFriendship(_ context.Context, a, b uint64) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	delete(m.s.friends, [2]uint64{a, b})
	delete(m.s.friends, [2]uint64{b, a})
	return nil
}

func (m *Memory) Friends(_ context.Context, user uint64) ([]Contact, error) {
	m.s.mu.Lock()
	var ids []uint64
	for k := range m.s.friends {
		if k[0] == user {
			ids = append(ids, k[1])
		}
	}
	m.s.mu.Unlock()
	return m.contacts(ids, nil), nil
}

func (m *Memory) SetBlock(_ context.Context, user, target uint64, level uint8) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	m.s.blocks[[2]uint64{user, target}] = level
	return nil
}

func (m *Memory) Blocks(_ context.Context, user uint64) ([]Contact, error) {
	m.s.mu.Lock()
	var ids []uint64
	levels := map[uint64]uint8{}
	for k, lv := range m.s.blocks {
		if k[0] == user {
			ids = append(ids, k[1])
			levels[k[1]] = lv
		}
	}
	m.s.mu.Unlock()
	return m.contacts(ids, levels), nil
}

func (m *Memory) IsBlocked(_ context.Context, user, target uint64) (bool, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	_, ok := m.s.blocks[[2]uint64{user, target}]
	return ok, nil
}

func (m *Memory) contacts(ids []uint64, levels map[uint64]uint8) []Contact {
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Contact, 0, len(ids))
	for _, id := range ids {
		out = append(out, Contact{UserID: id, Name: m.accounts[id].Name, Level: levels[id]})
	}
	return out
}

// --- PostgreSQL --------------------------------------------------------------

func (p *Postgres) Enqueue(ctx context.Context, m Message) (uint64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO mailbox (to_id, type, from_id, from_name, small, data, data2)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		int64(m.To), int64(m.Type), int64(m.From), m.FromName, int32(m.Small), m.Data, m.Data2).Scan(&id)
	return uint64(id), err
}

func (p *Postgres) Inbox(ctx context.Context, user uint64, offset, limit int) ([]Message, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, type, from_id, from_name, small, data, data2, created_at
		FROM mailbox WHERE to_id = $1 ORDER BY id OFFSET $2 LIMIT $3`, int64(user), offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		var id, typ, from int64
		var small int32
		if err := rows.Scan(&id, &typ, &from, &m.FromName, &small, &m.Data, &m.Data2, &m.Created); err != nil {
			return nil, err
		}
		m.ID, m.To, m.Type, m.From, m.Small = uint64(id), user, uint32(typ), uint64(from), uint16(small)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *Postgres) Ack(ctx context.Context, user, id uint64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM mailbox WHERE id = $1 AND to_id = $2`, int64(id), int64(user))
	return err
}

func (p *Postgres) AddFriendRequest(ctx context.Context, from, to uint64, data []byte) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO friend_requests (from_id, to_id, data) VALUES ($1, $2, $3)
		ON CONFLICT (from_id, to_id) DO UPDATE SET data = $3, created_at = now()`,
		int64(from), int64(to), data)
	return err
}

func (p *Postgres) RemoveFriendRequest(ctx context.Context, from, to uint64) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM friend_requests WHERE from_id = $1 AND to_id = $2`,
		int64(from), int64(to))
	return tag.RowsAffected() > 0, err
}

func (p *Postgres) FriendRequestsTo(ctx context.Context, to uint64) ([]Contact, error) {
	return p.contacts(ctx, `
		SELECT r.from_id, coalesce(a.name, ''), 0 FROM friend_requests r
		LEFT JOIN accounts a ON a.user_id = r.from_id WHERE r.to_id = $1 ORDER BY r.created_at`, to)
}

func (p *Postgres) AddFriendship(ctx context.Context, a, b uint64) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING`,
		int64(a), int64(b))
	return err
}

func (p *Postgres) RemoveFriendship(ctx context.Context, a, b uint64) error {
	_, err := p.pool.Exec(ctx, `
		DELETE FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)`,
		int64(a), int64(b))
	return err
}

func (p *Postgres) Friends(ctx context.Context, user uint64) ([]Contact, error) {
	return p.contacts(ctx, `
		SELECT f.friend_id, coalesce(a.name, ''), 0 FROM friends f
		LEFT JOIN accounts a ON a.user_id = f.friend_id WHERE f.user_id = $1 ORDER BY a.name`, user)
}

func (p *Postgres) SetBlock(ctx context.Context, user, target uint64, level uint8) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO blocks (user_id, blocked_id, level) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, blocked_id) DO UPDATE SET level = $3`, int64(user), int64(target), int16(level))
	return err
}

func (p *Postgres) Blocks(ctx context.Context, user uint64) ([]Contact, error) {
	return p.contacts(ctx, `
		SELECT b.blocked_id, coalesce(a.name, ''), b.level FROM blocks b
		LEFT JOIN accounts a ON a.user_id = b.blocked_id WHERE b.user_id = $1 ORDER BY a.name`, user)
}

func (p *Postgres) IsBlocked(ctx context.Context, user, target uint64) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blocks WHERE user_id = $1 AND blocked_id = $2)`,
		int64(user), int64(target)).Scan(&ok)
	return ok, err
}

func (p *Postgres) contacts(ctx context.Context, query string, user uint64) ([]Contact, error) {
	rows, err := p.pool.Query(ctx, query, int64(user))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		var id int64
		var level int16
		var c Contact
		if err := rows.Scan(&id, &c.Name, &level); err != nil {
			return nil, err
		}
		c.UserID, c.Level = uint64(id), uint8(level)
		out = append(out, c)
	}
	return out, rows.Err()
}
