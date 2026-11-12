package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// File is an uploaded storage file (lobby service 10), e.g. content offered in a
// trade. Flag and Visible are the two bits the game sends with an upload and reads
// back in file info, stored as received.
type File struct {
	ID       uint64
	Owner    uint64
	Name     string
	Flag     bool
	Visible  bool
	Data     []byte
	Created  time.Time
	Modified time.Time
}

type Files interface {
	CreateFile(ctx context.Context, f File) (uint64, error)
	File(ctx context.Context, id uint64) (File, error)
	// FilesByOwner lists an owner's files (without data); private ones only if
	// includePrivate.
	FilesByOwner(ctx context.Context, owner uint64, includePrivate bool, offset, limit int) ([]File, error)
	// UpdateFile changes data (if non-nil) and/or name and visibility (if name
	// is non-nil) of a file the owner holds; it reports whether one was changed.
	UpdateFile(ctx context.Context, owner, id uint64, data []byte, name *string, visible bool) (bool, error)
	DeleteFile(ctx context.Context, owner, id uint64) error
}

// --- in-memory -------------------------------------------------------------

type memFiles struct {
	next  uint64
	files map[uint64]File
}

func (m *Memory) CreateFile(_ context.Context, f File) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.f.files == nil {
		m.f.files = map[uint64]File{}
	}
	m.f.next++
	f.ID, f.Created, f.Modified = m.f.next, time.Now(), time.Now()
	m.f.files[f.ID] = f
	return f.ID, nil
}

func (m *Memory) File(_ context.Context, id uint64) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.f.files[id]
	if !ok {
		return f, ErrNotFound
	}
	return f, nil
}

func (m *Memory) FilesByOwner(_ context.Context, owner uint64, includePrivate bool, offset, limit int) ([]File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []File
	for _, f := range m.f.files {
		if f.Owner == owner && (f.Visible || includePrivate) {
			f.Data = nil
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if offset >= len(out) {
		return nil, nil
	}
	return out[offset:min(offset+limit, len(out))], nil
}

func (m *Memory) UpdateFile(_ context.Context, owner, id uint64, data []byte, name *string, visible bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.f.files[id]
	if !ok || f.Owner != owner {
		return false, nil
	}
	if data != nil {
		f.Data = data
	}
	if name != nil {
		f.Name, f.Visible = *name, visible
	}
	f.Modified = time.Now()
	m.f.files[id] = f
	return true, nil
}

func (m *Memory) DeleteFile(_ context.Context, owner, id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.f.files[id]; ok && f.Owner == owner {
		delete(m.f.files, id)
	}
	return nil
}

// --- PostgreSQL --------------------------------------------------------------

func (p *Postgres) CreateFile(ctx context.Context, f File) (uint64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO storage_files (owner, name, flag, visible, data) VALUES ($1, $2, $3, $4, $5)
		RETURNING id`, int64(f.Owner), f.Name, f.Flag, f.Visible, f.Data).Scan(&id)
	return uint64(id), err
}

const fileColumns = `id, owner, name, flag, visible, created_at, modified_at`

func scanFile(row pgx.Row, withData bool) (File, error) {
	var f File
	var id, owner int64
	dest := []any{&id, &owner, &f.Name, &f.Flag, &f.Visible, &f.Created, &f.Modified}
	if withData {
		dest = append(dest, &f.Data)
	}
	err := row.Scan(dest...)
	f.ID, f.Owner = uint64(id), uint64(owner)
	return f, err
}

func (p *Postgres) File(ctx context.Context, id uint64) (File, error) {
	f, err := scanFile(p.pool.QueryRow(ctx,
		`SELECT `+fileColumns+`, data FROM storage_files WHERE id = $1`, int64(id)), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (p *Postgres) FilesByOwner(ctx context.Context, owner uint64, includePrivate bool, offset, limit int) ([]File, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+fileColumns+` FROM storage_files
		WHERE owner = $1 AND (visible OR $2) ORDER BY id OFFSET $3 LIMIT $4`,
		int64(owner), includePrivate, offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		f, err := scanFile(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateFile(ctx context.Context, owner, id uint64, data []byte, name *string, visible bool) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE storage_files SET
			data = coalesce($3, data),
			name = coalesce($4, name),
			visible = CASE WHEN $4::text IS NULL THEN visible ELSE $5 END,
			modified_at = now()
		WHERE id = $1 AND owner = $2`, int64(id), int64(owner), data, name, visible)
	return tag.RowsAffected() > 0, err
}

func (p *Postgres) DeleteFile(ctx context.Context, owner, id uint64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM storage_files WHERE id = $1 AND owner = $2`, int64(id), int64(owner))
	return err
}
