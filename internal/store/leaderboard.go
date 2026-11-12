package store

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
)

// RankedRow is one leaderboard row as the game reads it: the player, their
// score, their rank on the board and the board's extra columns.
type RankedRow struct {
	UserID uint64
	Name   string
	Rating int64
	Rank   uint64 // 1-based; equal ratings share a rank
	Values []int32
}

// Leaderboards reads stored stats rows ranked by rating, highest first.
type Leaderboards interface {
	// StatsFor returns the rows of the given players (missing players are skipped).
	StatsFor(ctx context.Context, board int32, users []uint64) ([]RankedRow, error)
	// StatsFrom returns up to limit rows starting at a 1-based position.
	StatsFrom(ctx context.Context, board int32, position, limit int) ([]RankedRow, error)
	// StatsAround returns up to limit rows centred on a player; empty if they have no row.
	StatsAround(ctx context.Context, board int32, user uint64, limit int) ([]RankedRow, error)
}

// aroundStart is the 1-based position a window of limit rows centred on pos starts at.
func aroundStart(pos, limit int) int {
	return max(pos-limit/2, 1)
}

// --- in-memory -------------------------------------------------------------

// ranked returns a board's rows in leaderboard order with ranks filled in.
func (m *Memory) ranked(board int32) []RankedRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rows []RankedRow
	for k, r := range m.stats {
		if int32(k[1]) == board {
			rows = append(rows, RankedRow{UserID: uint64(k[0]), Name: m.accounts[uint64(k[0])].Name,
				Rating: r.Rating, Values: r.Values})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Rating != rows[j].Rating {
			return rows[i].Rating > rows[j].Rating
		}
		return rows[i].UserID < rows[j].UserID
	})
	for i := range rows {
		rows[i].Rank = uint64(i + 1)
		if i > 0 && rows[i].Rating == rows[i-1].Rating {
			rows[i].Rank = rows[i-1].Rank
		}
	}
	return rows
}

func (m *Memory) StatsFor(_ context.Context, board int32, users []uint64) ([]RankedRow, error) {
	want := map[uint64]bool{}
	for _, u := range users {
		want[u] = true
	}
	var out []RankedRow
	for _, r := range m.ranked(board) {
		if want[r.UserID] {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *Memory) StatsFrom(_ context.Context, board int32, position, limit int) ([]RankedRow, error) {
	rows := m.ranked(board)
	start := max(position, 1) - 1
	if start >= len(rows) {
		return nil, nil
	}
	return rows[start:min(start+limit, len(rows))], nil
}

func (m *Memory) StatsAround(ctx context.Context, board int32, user uint64, limit int) ([]RankedRow, error) {
	for i, r := range m.ranked(board) {
		if r.UserID == user {
			return m.StatsFrom(ctx, board, aroundStart(i+1, limit), limit)
		}
	}
	return nil, nil
}

// --- PostgreSQL --------------------------------------------------------------

// boardSQL ranks one board; pos is the row's place in display order (for paging).
const boardSQL = `
	SELECT s.user_id, coalesce(a.name, '') AS name, s.rating, s.vals,
	       rank() OVER (ORDER BY s.rating DESC) AS rank,
	       row_number() OVER (ORDER BY s.rating DESC, s.user_id) AS pos
	FROM stats s LEFT JOIN accounts a ON a.user_id = s.user_id
	WHERE s.board = $1`

func (p *Postgres) StatsFor(ctx context.Context, board int32, users []uint64) ([]RankedRow, error) {
	ids := make([]int64, len(users))
	for i, u := range users {
		ids[i] = int64(u)
	}
	return p.rankedRows(ctx, `SELECT user_id, name, rating, vals, rank FROM (`+boardSQL+`) b
		WHERE user_id = ANY($2) ORDER BY pos`, board, ids)
}

func (p *Postgres) StatsFrom(ctx context.Context, board int32, position, limit int) ([]RankedRow, error) {
	return p.rankedRows(ctx, `SELECT user_id, name, rating, vals, rank FROM (`+boardSQL+`) b
		WHERE pos >= $2 ORDER BY pos LIMIT $3`, board, max(position, 1), limit)
}

func (p *Postgres) StatsAround(ctx context.Context, board int32, user uint64, limit int) ([]RankedRow, error) {
	var pos int
	err := p.pool.QueryRow(ctx, `SELECT pos FROM (`+boardSQL+`) b WHERE user_id = $2`,
		board, int64(user)).Scan(&pos)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // no row on this board: nothing to centre on
	} else if err != nil {
		return nil, err
	}
	return p.StatsFrom(ctx, board, aroundStart(pos, limit), limit)
}

func (p *Postgres) rankedRows(ctx context.Context, query string, args ...any) ([]RankedRow, error) {
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RankedRow
	for rows.Next() {
		var r RankedRow
		var id, rank int64
		if err := rows.Scan(&id, &r.Name, &r.Rating, &r.Values, &rank); err != nil {
			return nil, err
		}
		r.UserID, r.Rank = uint64(id), uint64(rank)
		out = append(out, r)
	}
	return out, rows.Err()
}
