package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Postgres stores everything in PostgreSQL. User ids are stored as bigint (the
// uint64 reinterpreted as signed).
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects and applies the schema (idempotent).
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) CreateAccount(ctx context.Context, a Account) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO accounts (user_id, name, password_tiger) VALUES ($1, $2, $3)`,
		int64(a.UserID), a.Name, a.PasswordTiger)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return ErrExists
	}
	return err
}

func (p *Postgres) Account(ctx context.Context, id uint64) (Account, error) {
	a := Account{UserID: id}
	err := p.pool.QueryRow(ctx,
		`SELECT name, password_tiger FROM accounts WHERE user_id = $1`,
		int64(id)).Scan(&a.Name, &a.PasswordTiger)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (p *Postgres) TouchLogin(ctx context.Context, id uint64) error {
	_, err := p.pool.Exec(ctx, `UPDATE accounts SET last_login = now() WHERE user_id = $1`, int64(id))
	return err
}

func (p *Postgres) PublicProfile(ctx context.Context, id uint64) (PublicProfile, error) {
	var pp PublicProfile
	err := p.pool.QueryRow(ctx,
		`SELECT public_a, public_b, public_data FROM profiles WHERE user_id = $1 AND public_data IS NOT NULL`,
		int64(id)).Scan(&pp.A, &pp.B, &pp.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return pp, ErrNotFound
	}
	return pp, err
}

func (p *Postgres) SetPublicProfile(ctx context.Context, id uint64, pp PublicProfile) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO profiles (user_id, public_a, public_b, public_data) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE
		SET public_a = $2, public_b = $3, public_data = $4, updated_at = now()`,
		int64(id), pp.A, pp.B, pp.Data)
	return err
}

func (p *Postgres) PrivateProfile(ctx context.Context, id uint64) (PrivateProfile, error) {
	var vals []int32
	err := p.pool.QueryRow(ctx,
		`SELECT private FROM profiles WHERE user_id = $1 AND private IS NOT NULL`,
		int64(id)).Scan(&vals)
	var pp PrivateProfile
	if errors.Is(err, pgx.ErrNoRows) {
		return pp, ErrNotFound
	}
	copy(pp[:], vals)
	return pp, err
}

func (p *Postgres) SetPrivateProfile(ctx context.Context, id uint64, pp PrivateProfile) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO profiles (user_id, private) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET private = $2, updated_at = now()`,
		int64(id), pp[:])
	return err
}

func (p *Postgres) DeleteProfile(ctx context.Context, id uint64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM profiles WHERE user_id = $1`, int64(id))
	return err
}

func (p *Postgres) WriteStats(ctx context.Context, id uint64, r StatsRow) error {
	if r.Values == nil {
		r.Values = []int32{} // NOT NULL column; rating-only boards have no extra values
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO stats (user_id, board, flag, rating, vals) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, board) DO UPDATE
		SET flag = $3, rating = $4, vals = $5, updated_at = now()`,
		int64(id), r.Board, int16(r.Flag), r.Rating, r.Values)
	return err
}
