package lobby

import (
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
)

// Quick Match search captured from the retail game: type 1, 50 results, any match
// type [0,85], rank 0 in window 0..10, entrance/CAS any, country any.
const capturedQuickMatch = "c7c110180503e0040000001c190000800300000070000000000e000000c0a9020000380000000007000000e028" +
	"0000001c000000801300000070000000004e000000c0010000003800000000c7010000e0000000001c00000080" +
	"0300000078feffffff0000000000000000"

// hostedSession mirrors a session the retail game hosted (values from the capture,
// with a placeholder address): ranked 1, CAS 1, entrance 1, match type 0, rank 0
// with window 0..10, slots 2 public / 0 used. edit adjusts game fields by index.
func hostedSession(edit map[int]int32) []bitbuf.Field {
	i32 := func(v int32) bitbuf.Field { return bitbuf.Int(bitbuf.I32, uint64(uint32(v))) }
	game := []int32{1, 0 /* name */, 0, 1, 0, -1 << 31, 1<<31 - 1, 1, 1, 0, 0, 0, 0, 10, 0, 0, 0}
	for k, v := range edit {
		game[k] = v
	}
	info := []bitbuf.Field{bitbuf.Bytes(bitbuf.Blob, make([]byte, 25)), bitbuf.Bytes(bitbuf.Blob, make([]byte, 8)),
		bitbuf.Bytes(bitbuf.Blob, make([]byte, 16)), i32(2), i32(0), i32(0), i32(0)}
	for k, v := range game {
		if k == 1 {
			info = append(info, bitbuf.Bytes(bitbuf.String, []byte("bbbb")))
			continue
		}
		info = append(info, i32(v))
	}
	return info
}

func quickMatch(t *testing.T) searchQuery {
	b, _ := hex.DecodeString(capturedQuickMatch)
	r, _ := bitbuf.NewReader(b)
	r.U8()
	r.U8()
	r.U8()
	fields, err := r.Fields()
	if err != nil {
		t.Fatal(err)
	}
	return parseQuery(fields[1:])
}

func TestCapturedQueryParses(t *testing.T) {
	q := quickMatch(t)
	if q.kind != 1 || q.maxResults != 50 || !q.filters || q.matchLow != 0 || q.matchHi != 85 ||
		q.rank != 0 || q.rankLow != 0 || q.rankHigh != 10 || q.entLow != 0 || q.entHigh != 1 ||
		q.casLow != 0 || q.casHigh != 1 || q.countryLow != -1<<31 || q.countryHigh != 1<<31-1 {
		t.Fatalf("%+v", q)
	}
}

func TestSearchFilters(t *testing.T) {
	q := quickMatch(t)
	if ok, _ := q.matches(hostedSession(nil)); !ok {
		t.Fatal("captured quick match should find the captured host session")
	}
	for name, edit := range map[string]map[int]int32{
		"unranked host":         {gRanked: 0},
		"host above rank range": {gRankSelf: 11},
		"searcher outside host": {gRankLow: 3, gRankHigh: 10},
		"match type off range":  {gMatchType: 90},
		"country refused":       {gCountryLow: 5, gCountryHigh: 5},
	} {
		if ok, _ := q.matches(hostedSession(edit)); ok {
			t.Errorf("%s: matched", name)
		}
	}
	// A specific rule, and entrance "no".
	q2 := q
	q2.matchLow, q2.matchHi = 14, 14
	if ok, _ := q2.matches(hostedSession(nil)); ok {
		t.Error("rule 14 matched a match-type-0 session")
	}
	if ok, _ := q2.matches(hostedSession(map[int]int32{gMatchType: 14})); !ok {
		t.Error("rule 14 missed a match-type-14 session")
	}
	q3 := q
	q3.entLow, q3.entHigh = 0, 0
	if ok, _ := q3.matches(hostedSession(nil)); ok {
		t.Error("entrance=no matched a session with entrances")
	}
	// Unranked searches find unranked sessions only.
	q4 := q
	q4.kind = queryUnrankedOnly
	if ok, _ := q4.matches(hostedSession(nil)); ok {
		t.Error("unranked search found a ranked session")
	}
	if ok, _ := q4.matches(hostedSession(map[int]int32{gRanked: 0})); !ok {
		t.Error("unranked search missed an unranked session")
	}
}

func TestFullSessionsHidden(t *testing.T) {
	q := quickMatch(t)
	full := hostedSession(nil)
	full[slotPublicUsed] = bitbuf.Int(bitbuf.I32, 2)
	if ok, _ := q.matches(full); ok {
		t.Error("full session listed")
	}
	invite := hostedSession(nil)
	invite[slotPublicMax] = bitbuf.Int(bitbuf.I32, 0)
	if ok, _ := q.matches(invite); ok {
		t.Error("invite-only session listed")
	}
}

func TestSearchOrdersByRankDistance(t *testing.T) {
	m := NewMatchmaking(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i, rank := range []int32{5, 1, 3} {
		info := hostedSession(map[int]int32{gRankSelf: rank})
		id := [8]byte{byte(i)}
		m.sessions[id] = &mmSession{owner: i, info: info, order: uint64(i)}
	}
	q := quickMatch(t)
	q.rank = 2
	got := m.search("searcher", q)
	var ranks []uint64
	for _, info := range got {
		ranks = append(ranks, info[sessBase+gRankSelf].Int)
	}
	if len(ranks) != 3 || ranks[0] != 1 || ranks[1] != 3 || ranks[2] != 5 {
		t.Fatalf("order %v", ranks)
	}
}
