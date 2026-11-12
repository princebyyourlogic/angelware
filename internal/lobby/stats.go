package lobby

import (
	"context"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Stats, lobby service 4 (senders LBYM 0x6e2c8..0x6ecb8, lobby tasks 0x22..0x29
// and WriteDna):
//
//	1 write(u8, u8 flag, i32 board, u64 0, i64 rating, i32 values...)
//	2 delete(u8, i32 board, u64 user): user 0 is the caller; sent per board of a
//	  group, e.g. when a player no longer holds a belt (prestige boards 19-26)
//	3 read players(u8, i32 board, u64 user)
//	4 read players(u8, i32 board, u32 n, n x u64 user)
//	5 read range(u8, i32 board, u64 user, u64 position, i64 count)
//	  user != 0: rows around that player; user == 0: rows from a 1-based position
//	6 read filtered(u8, u64, object): answered with no rows
//
// Read results (0x6ef98, list 0xbf778): u32 count, u32 total rows on the board
// (0x6f6e0, GetReadStatsTotalEntries), then rows of u64 user, i64 rating, u64 rank,
// string name (0x6f328), followed by the board's columns exactly as the game
// wrote them (board 1: 12 x i32, 10: 32, 19 and 23: 6, score-only boards: none).
const (
	statsWrite      = 1
	statsDelete     = 2
	statsReadUser   = 3
	statsReadUsers  = 4
	statsReadRange  = 5
	statsReadFilter = 6
	statsMaxRows    = 100
)

func (c *Conn) stats(ctx context.Context, t Task) []byte {
	if t.ID >= statsReadUser && t.ID <= statsReadFilter {
		return c.statsRead(ctx, t)
	}
	if t.ID == statsDelete {
		return c.statsDelete(ctx, t)
	}
	if t.ID != statsWrite {
		return Reply(t, nil)
	}
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 5 {
		c.log.Warn("stats write did not parse", "err", err, "fields", len(fields))
		return Reply(t, nil)
	}
	// Boards 2-9, 11-18, 20-22 and 24-26 carry only the rating: keep an empty list.
	row := store.StatsRow{Flag: uint8(fields[1].Int), Board: int32(fields[2].Int), Rating: int64(fields[4].Int),
		Values: []int32{}}
	for _, f := range fields[5:] {
		if f.Type == bitbuf.I32 {
			row.Values = append(row.Values, int32(f.Int))
		}
	}
	if err := c.srv.Store.WriteStats(ctx, c.sess.UserID, row); err != nil {
		c.log.Error("save stats", "err", err)
	}
	c.log.Debug("stats written", "board", row.Board, "rating", row.Rating, "values", len(row.Values))
	return Reply(t, nil)
}

func (c *Conn) statsRead(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 2 || t.ID == statsReadFilter {
		if err != nil {
			c.log.Warn("stats read did not parse", "task", t.ID, "err", err)
		}
		return statsReply(t, nil, 0)
	}
	board := int32(fields[1].Int)
	args := fields[2:]
	st := c.srv.Store
	var rows []store.RankedRow
	switch t.ID {
	case statsReadUser, statsReadUsers:
		var users []uint64
		for _, f := range args {
			if f.Type == bitbuf.U64 {
				users = append(users, f.Int)
			}
		}
		rows, err = st.StatsFor(ctx, board, users)
	case statsReadRange:
		if len(args) < 3 {
			return statsReply(t, nil, 0)
		}
		user, position := args[0].Int, int(args[1].Int)
		limit := min(int(int64(args[2].Int)), statsMaxRows)
		if user != 0 {
			rows, err = st.StatsAround(ctx, board, user, limit)
		} else {
			rows, err = st.StatsFrom(ctx, board, position, limit)
		}
	}
	if err != nil {
		c.log.Error("read stats", "board", board, "err", err)
		return statsReply(t, nil, 0)
	}
	total, err := st.StatsTotal(ctx, board)
	if err != nil {
		c.log.Error("count stats", "board", board, "err", err)
	}
	c.log.Debug("stats read", "task", t.ID, "board", board, "rows", len(rows), "total", total)
	return statsReply(t, rows, total)
}

// statsReply is the read result: u32 count, u32 total, rows.
func statsReply(t Task, rows []store.RankedRow, total int) []byte {
	out := []bitbuf.Field{bitbuf.Int(bitbuf.U32, uint64(total))}
	for _, r := range rows {
		out = append(out, bitbuf.Int(bitbuf.U64, r.UserID), bitbuf.Int(bitbuf.I64, uint64(r.Rating)),
			bitbuf.Int(bitbuf.U64, r.Rank), bitbuf.Bytes(bitbuf.String, []byte(truncate(r.Name, 63))))
		for _, v := range r.Values {
			out = append(out, bitbuf.Int(bitbuf.I32, uint64(uint32(v))))
		}
	}
	return ListReply(t, uint32(len(rows)), out)
}

// statsDelete removes the caller's row on a board. A player can only delete
// their own rows.
func (c *Conn) statsDelete(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 3 {
		c.log.Warn("stats delete did not parse", "err", err)
		return Reply(t, nil)
	}
	board, user := int32(fields[1].Int), fields[2].Int
	if user != 0 && user != c.sess.UserID {
		c.log.Warn("stats delete for another player refused", "board", board)
		return Reply(t, nil)
	}
	if err := c.srv.Store.DeleteStats(ctx, c.sess.UserID, board); err != nil {
		c.log.Error("delete stats", "board", board, "err", err)
	}
	c.log.Info("stats deleted", "board", board)
	return Reply(t, nil)
}
