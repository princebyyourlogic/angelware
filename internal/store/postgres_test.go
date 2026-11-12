package store

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Runs against a real database when ANGELWARE_TEST_DATABASE_URL is set, e.g.
// postgres://angelware:test@localhost:55499/angelware?sslmode=disable
func TestPostgres(t *testing.T) {
	url := os.Getenv("ANGELWARE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ANGELWARE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// Schema is idempotent: opening twice must work.
	if p2, err := OpenPostgres(ctx, url); err != nil {
		t.Fatal(err)
	} else {
		p2.Close()
	}

	var id uint64 = 0xfd48752c82ac6ca9 // high bit set: stored as negative bigint
	p.pool.Exec(ctx, `DELETE FROM accounts WHERE user_id = $1`, int64(id))
	p.DeleteProfile(ctx, id)

	acct := Account{UserID: id, Name: "pgtest", PasswordTiger: make([]byte, 24)}
	if err := p.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAccount(ctx, acct); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate account: %v", err)
	}
	if got, err := p.Account(ctx, id); err != nil || got.Name != "pgtest" {
		t.Fatalf("account %+v %v", got, err)
	}
	if _, err := p.Account(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account: %v", err)
	}

	if _, err := p.PrivateProfile(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing private profile: %v", err)
	}
	if err := p.SetPublicProfile(ctx, id, PublicProfile{A: 1, B: -2, Data: []byte{9}}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPrivateProfile(ctx, id, PrivateProfile{1, 0, 0, 3}); err != nil {
		t.Fatal(err)
	}
	if pp, err := p.PrivateProfile(ctx, id); err != nil || pp != (PrivateProfile{1, 0, 0, 3}) {
		t.Fatalf("private %v %v", pp, err)
	}
	if pub, err := p.PublicProfile(ctx, id); err != nil || pub.B != -2 || pub.Data[0] != 9 {
		t.Fatalf("public %+v %v", pub, err)
	}
	for i := 0; i < 2; i++ {
		if err := p.WriteStats(ctx, id, StatsRow{Board: 1, Rating: int64(i), Values: []int32{1, 2}}); err != nil {
			t.Fatal(err)
		}
	}
	// Rating-only boards (2-9 etc.) write no extra values.
	if err := p.WriteStats(ctx, id, StatsRow{Board: 3, Rating: 1}); err != nil {
		t.Fatalf("rating-only board: %v", err)
	}

	// Social: requests, friendship, blocks and the mailbox survive in the database.
	var other uint64 = 0x0123456789abcdef
	p.pool.Exec(ctx, `DELETE FROM friend_requests WHERE from_id = $1 OR to_id = $1`, int64(id))
	p.pool.Exec(ctx, `DELETE FROM friends WHERE user_id = $1 OR friend_id = $1`, int64(id))
	p.pool.Exec(ctx, `DELETE FROM blocks WHERE user_id = $1`, int64(other))
	p.pool.Exec(ctx, `DELETE FROM mailbox WHERE to_id = $1`, int64(other))
	if created, err := p.AddFriendRequest(ctx, id, other, []byte("hi")); !created || err != nil {
		t.Fatalf("first request %v %v", created, err)
	}
	if created, err := p.AddFriendRequest(ctx, id, other, nil); created || err != nil {
		t.Fatalf("repeated request stored again: %v %v", created, err)
	}
	if reqs, err := p.FriendRequestsTo(ctx, other); err != nil || len(reqs) != 1 || reqs[0].Name != "pgtest" {
		t.Fatalf("requests %+v %v", reqs, err)
	}
	if ok, err := p.RemoveFriendRequest(ctx, id, other); !ok || err != nil {
		t.Fatalf("remove request %v %v", ok, err)
	}
	if err := p.AddFriendship(ctx, id, other); err != nil {
		t.Fatal(err)
	}
	if fr, err := p.Friends(ctx, other); err != nil || len(fr) != 1 || fr[0].UserID != id {
		t.Fatalf("friends %+v %v", fr, err)
	}
	if ok, err := p.AreFriends(ctx, other, id); !ok || err != nil {
		t.Fatalf("AreFriends %v %v", ok, err)
	}
	p.RemoveFriendship(ctx, other, id)
	if fr, _ := p.Friends(ctx, id); len(fr) != 0 {
		t.Fatalf("friendship not removed: %+v", fr)
	}
	p.SetBlock(ctx, other, id, 2)
	if b, err := p.Blocks(ctx, other); err != nil || len(b) != 1 || b[0].Level != 2 {
		t.Fatalf("blocks %+v %v", b, err)
	}
	if blocked, _ := p.IsBlocked(ctx, other, id); !blocked {
		t.Fatal("block not found")
	}
	mid, err := p.Enqueue(ctx, Message{To: other, Type: 5, From: id, FromName: "pgtest", Small: 7,
		Data: []byte{1}, Data2: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := p.Inbox(ctx, other, 0, 20)
	if err != nil || len(inbox) != 1 || inbox[0].ID != mid || inbox[0].Small != 7 || inbox[0].Data2[0] != 2 {
		t.Fatalf("inbox %+v %v", inbox, err)
	}
	p.Ack(ctx, id, mid) // wrong recipient: kept
	if inbox, _ := p.Inbox(ctx, other, 0, 20); len(inbox) != 1 {
		t.Fatal("ack by another user removed the message")
	}
	p.Ack(ctx, other, mid)
	if inbox, _ := p.Inbox(ctx, other, 0, 20); len(inbox) != 0 {
		t.Fatal("ack did not remove the message")
	}

	// Leaderboard ranking on a board of its own.
	const lb = 9001
	p.pool.Exec(ctx, `DELETE FROM stats WHERE board = $1`, lb)
	for i, rating := range []int64{10, 30, 20, 30} {
		p.WriteStats(ctx, uint64(1000+i), StatsRow{Board: lb, Rating: rating, Values: []int32{int32(i)}})
	}
	top, err := p.StatsFrom(ctx, lb, 1, 10)
	if err != nil || len(top) != 4 || top[0].Rating != 30 || top[1].Rating != 30 || top[1].Rank != 2 ||
		top[2].Rank != 3 || top[3].Rank != 4 {
		t.Fatalf("StatsFrom %+v %v", top, err)
	}
	if rows, err := p.StatsFor(ctx, lb, []uint64{1000, 77}); err != nil || len(rows) != 1 || rows[0].Rank != 4 {
		t.Fatalf("StatsFor %+v %v", rows, err)
	}
	if rows, err := p.StatsAround(ctx, lb, 1000, 2); err != nil || len(rows) != 2 || rows[1].UserID != 1000 {
		t.Fatalf("StatsAround %+v %v", rows, err)
	}
	if rows, err := p.StatsAround(ctx, lb, 77, 2); err != nil || len(rows) != 0 {
		t.Fatalf("StatsAround missing %+v %v", rows, err)
	}
	if err := p.DeleteStats(ctx, 1000, lb); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.StatsTotal(ctx, lb); n != 3 {
		t.Fatalf("after delete %d rows", n)
	}
	p.pool.Exec(ctx, `DELETE FROM stats WHERE board = $1`, lb)

	// Storage files.
	fid, err := p.CreateFile(ctx, File{Owner: id, Name: "pg", Flag: true, Visible: false, Data: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if fs, err := p.FilesByOwner(ctx, id, false, 0, 10); err != nil || len(fs) != 0 {
		t.Fatalf("private file listed to others %v %v", fs, err)
	}
	n := "renamed"
	if ok, err := p.UpdateFile(ctx, id, fid, nil, &n, true); !ok || err != nil {
		t.Fatalf("rename %v %v", ok, err)
	}
	if ok, _ := p.UpdateFile(ctx, 77, fid, []byte{9}, nil, false); ok {
		t.Fatal("update by another owner")
	}
	if ok, err := p.UpdateFile(ctx, id, fid, []byte{4, 5}, nil, false); !ok || err != nil {
		t.Fatalf("update data %v %v", ok, err)
	}
	f, err := p.File(ctx, fid)
	if err != nil || f.Name != "renamed" || !f.Visible || !f.Flag || len(f.Data) != 2 {
		t.Fatalf("file %+v %v", f, err)
	}
	if fs, _ := p.FilesByOwner(ctx, id, false, 0, 10); len(fs) != 1 || fs[0].Data != nil || fs[0].Size != 2 {
		t.Fatalf("public listing %+v", fs)
	}
	p.DeleteFile(ctx, id, fid)
	if _, err := p.File(ctx, fid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted file %v", err)
	}
}
