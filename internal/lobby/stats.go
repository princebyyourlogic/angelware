package lobby

import (
	"context"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Stats, lobby service 4 (lobby tasks 0x22..0x29 and WriteDna):
//
//	1 write(u8, u8 flag, i32 board, u64, i64 rating, i32 values...)
//	3 read(u8, i32 board, u64 user)
//
// Writes are stored. The read result layout has not been decoded yet, so reads
// still get an empty success, which the game tolerates.
const (
	statsWrite = 1
)

func (c *Conn) stats(ctx context.Context, t Task) []byte {
	if t.ID != statsWrite {
		// Reads (3-6) are lists; leaderboards are not served yet.
		if t.ID >= 3 && t.ID <= 6 {
			return ListReply(t, 0, nil)
		}
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
