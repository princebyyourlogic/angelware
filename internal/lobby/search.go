package lobby

import (
	"sort"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
)

// Search filtering for matchmaking task 5.
//
// Query (DemonWare object 0x26ce8, serializer 0x26db8; filled by OMEN
// COnlineMatchDataCtrl::SearchSession 0x2db0 from a CSearchCondition):
//
//	i32 type         1 or 2 = the searcher's ranked flag (condition[2] == 1), 3 = mode 1
//	i32 max results  (50)
//	i32 0, i32 mode  when mode != 0 nothing follows
//	i32 match type low, high     [0, 85] = any rule (OMEN 0x8658 / 0x8760)
//	i32 rank self, min, max      stars from points; window from the menu (default 0..10)
//	i32 entrance low, high       yes/no/any = [1,1] / [0,0] / [0,1]
//	i32 CAS low, high            same, for created superstars
//	i32 country, 0, 14, bool, bool (condition[3] == 2)    not filtered on
//	i32 country range low, high  (unbounded by default)
//
// Session info game fields (serializer 0x27c90, after the 7 DemonWare base fields:
// blob address, id, key, slots public max/used, private max/used):
//
//	0 ranked  1 name  2 arena  3 CAS  4 country  5,6 country range  7 entrance
//	8 manager  9 match type  10 PAL50  11,12,13 rank self/min/max  14 title match
//	15 session mode ...
//
// The original server's queries are not known; these checks follow how the game
// pairs each query value with a session field ("value + accepted range" both ways).
const (
	sessBase       = 7 // DemonWare base fields before the game's
	slotPublicMax  = 3
	slotPublicUsed = 4

	gRanked      = 0
	gCAS         = 3
	gCountry     = 4
	gCountryLow  = 5
	gCountryHigh = 6
	gEntrance    = 7
	gMatchType   = 9
	gRankSelf    = 11
	gRankLow     = 12
	gRankHigh    = 13

	queryRankedOnly   = 1
	queryUnrankedOnly = 2
)

type searchQuery struct {
	kind              int32 // 1 ranked, 2 unranked, 3 other mode
	maxResults        int
	filters           bool // false when the query carries only its header (mode != 0)
	matchLow, matchHi int32
	rank, rankLow     int32
	rankHigh          int32
	entLow, entHigh   int32
	casLow, casHigh   int32
	country           int32
	countryLow        int32
	countryHigh       int32
}

func parseQuery(args []bitbuf.Field) searchQuery {
	v := func(i int) int32 {
		if i < len(args) {
			return int32(uint32(args[i].Int))
		}
		return 0
	}
	q := searchQuery{kind: v(0), maxResults: int(v(1))}
	if v(3) != 0 || len(args) < 20 {
		return q
	}
	q.filters = true
	q.matchLow, q.matchHi = v(4), v(5)
	q.rank, q.rankLow, q.rankHigh = v(6), v(7), v(8)
	q.entLow, q.entHigh = v(9), v(10)
	q.casLow, q.casHigh = v(11), v(12)
	q.country = v(13)
	q.countryLow, q.countryHigh = v(18), v(19)
	return q
}

func in(v, low, high int32) bool { return low <= v && v <= high }

// matches reports whether a stored session suits a query, and how far its host's
// rank is from the searcher's (for ordering).
func (q searchQuery) matches(info []bitbuf.Field) (bool, int32) {
	num := func(i int) (int32, bool) {
		if i >= len(info) || info[i].Type != bitbuf.I32 {
			return 0, false
		}
		return int32(uint32(info[i].Int)), true
	}
	game := func(i int) (int32, bool) { return num(sessBase + i) }

	// Full or invite-only sessions never show up in a search.
	if pubMax, ok := num(slotPublicMax); ok {
		if used, _ := num(slotPublicUsed); used >= pubMax {
			return false, 0
		}
	}
	if q.kind == queryRankedOnly || q.kind == queryUnrankedOnly {
		want := int32(0)
		if q.kind == queryRankedOnly {
			want = 1
		}
		if ranked, ok := game(gRanked); ok && (ranked != 0) != (want != 0) {
			return false, 0
		}
	}
	if !q.filters {
		return true, 0
	}
	distance := int32(0)
	if self, ok := game(gRankSelf); ok {
		low, _ := game(gRankLow)
		high, _ := game(gRankHigh)
		if !in(self, q.rankLow, q.rankHigh) || !in(q.rank, low, high) {
			return false, 0
		}
		distance = self - q.rank
		if distance < 0 {
			distance = -distance
		}
	}
	if mt, ok := game(gMatchType); ok && !in(mt, q.matchLow, q.matchHi) {
		return false, 0
	}
	if ent, ok := game(gEntrance); ok && !in(ent, q.entLow, q.entHigh) {
		return false, 0
	}
	if cas, ok := game(gCAS); ok && !in(cas, q.casLow, q.casHigh) {
		return false, 0
	}
	if c, ok := game(gCountry); ok {
		low, _ := game(gCountryLow)
		high, _ := game(gCountryHigh)
		if !in(c, q.countryLow, q.countryHigh) || !in(q.country, low, high) {
			return false, 0
		}
	}
	return true, distance
}

type candidate struct {
	s        *mmSession
	distance int32
	order    uint64
}

// search returns the sessions matching a query, closest rank first, then oldest.
func (m *Matchmaking) search(owner any, q searchQuery) [][]bitbuf.Field {
	limit := q.maxResults
	if limit <= 0 || limit > mmMaxResults {
		limit = mmMaxResults
	}
	m.mu.RLock()
	var found []candidate
	for _, s := range m.sessions {
		if s.owner == owner {
			continue
		}
		if ok, d := q.matches(s.info); ok {
			found = append(found, candidate{s, d, s.order})
		}
	}
	m.mu.RUnlock()
	sort.Slice(found, func(i, j int) bool {
		if found[i].distance != found[j].distance {
			return found[i].distance < found[j].distance
		}
		return found[i].order < found[j].order
	})
	out := make([][]bitbuf.Field, 0, min(len(found), limit))
	for _, c := range found[:min(len(found), limit)] {
		out = append(out, c.s.info)
	}
	return out
}
