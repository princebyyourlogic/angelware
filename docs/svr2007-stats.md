# SvR 2007 online stats, rankings and ranks

How WWE SmackDown vs. Raw 2007 uses DemonWare stats, read from the game code. **Confirmed** = read
from the decompiled code (addresses below); **inferred** = names or meaning not spelled out in the code.
Addresses are offsets into the decompressed overlays (base 0): `LBYM` (DemonWare and lobby manager),
`OMEN` (online menu: match results, stats writes, matchmaking), `OME2` (ranking screens).

## The short version

- The **client** computes everything: points, wins, streaks, rates and belt prestige. After each match
  it takes its record (the board-1 / board-10 rows the **server returned at login**), adds the match,
  and writes the new totals back. The server's stored rows are the source of truth between sessions.
- The **server** stores each row as written, ranks every board by its rating (highest first), returns
  rows with rank and name, and deletes rows when asked (belt lost). It computes nothing else.
- The game **uses the rank it gets back**: the ranking list opens around the player's own rank. Points
  also drive the matchmaking "superstar rank" stars.

## Categories, boards and ranking tabs

The game writes and reads *categories*; `LBYM FUN_0002a108` maps a category to a board (confirmed).
One write of the group's first category produces every board of the group: `FUN_0002a218` mode 0
loops over the category tables at `LBYM 0xce0c0`, `0xce0e8`, `0xce110`, `0xce128`, and each board's
rating is chosen by the row class's `SetStatsInfo(board, record)`.

| Boards | Categories | Group (written by `OMEN FUN_00017a18`) | Ranking screen (`OME2`, tab table `0x3ee70`) |
| --- | --- | --- | --- |
| 1-9 | 1,2 → 1; 3..10 → 2..9 | Total record, `WriteStats(1)` after every online match | Total Ranking: tabs = categories 2..10 (boards 1..9) |
| 10-18 | 11,12 → 10; 13..20 → 11..18 | Title match record, `WriteStats(0xb)` (only after title matches, inferred from captures) | Title Match Ranking: categories 12..20 (boards 10..18) |
| 19-22 | 21,22 → 19; 23..25 → 20..22 | Single belt prestige, `WriteStats(0x15)` or `DeleteStats(0x15)` | Single Title Prestige Ranking: categories 22..25 (boards 19..22) |
| 23-26 | 26,27 → 23; 28..30 → 24..26 | Tag belt prestige, `WriteStats(0x1a)` or `DeleteStats(0x1a)` | Tag Title Prestige Ranking: categories 27..30 (boards 23..26) |
| 27 | DNA | Gameplay telemetry, `WriteDna` at login | none (never read) |

Each ranking screen has one tab per board in its group (left/right on the pad switches the category
read; first tabs are boards 1, 10, 19, 23, matching the captured reads).

### Rating (sort key) of every board (confirmed: `SetStatsInfo` switch statements)

| Board | Rating = record field | Meaning |
| --- | --- | --- |
| 1 | 0x4c | **Points** (total) |
| 2 | 0x50 | Wins |
| 3 | 0x54 | Losses |
| 4 | 0x58 | Draws |
| 5 | 0x5c | Losses with match finish type 3 (inferred: a specific loss type such as DQ/count-out) |
| 6 | 0x60 | Current win streak |
| 7 | 0x64 | Best win streak |
| 8 | 0x70 | Win rate, per mille |
| 9 | 0x74 | Disconnect rate, per mille (inferred, see below) |
| 10-18 | same fields of the **title** record | as 1-9 for title matches (`CDWTitleStatsInfo::SetStatsInfo` 0xbd690) |
| 19 | 0x4c | Single belt **Prestige** (`CDWSinglePrestigeStatsInfo::SetStatsInfo` 0xbeaa8) |
| 20 | 0x50 | Single belt: matches |
| 21 | 0x54 | Single belt: moves (belt moved hands, inferred) |
| 22 | 0x58 | Single belt: title defences |
| 23-26 | same as 19-22 | Tag belt (`CDWTagPrestigeStatsInfo::SetStatsInfo` 0xbf158) |

Sort: the read request has no order field (`LBYM 0x6e9b0`), so ordering is the server's. DemonWare
ranks by rating, highest first; keep that for every board, including losses and the disconnect rate.

## Row layouts (what the server stores and returns)

Read row: `u64 user, i64 rating, u64 rank, string name (≤63)`, then the board's columns. Only the
first board of a group carries columns (writers check the row kind: total 1, title 10, single 0x13,
tag 0x17); the other boards are rating-only. The game reads back exactly what it writes.

### Board 1: total record, 12 × i32 (`CDWTotalStatsInfo`, writer 0xbcf10, reader 0xbd108)

Filled in `OMEN FUN_00017a18` state 8, case 0 (confirmed). Captured values are bbbbb (one win) / cccc (two losses).

| Col | Field | Meaning | How the client updates it | bbbbb | cccc |
| --- | --- | --- | --- | --- | --- |
| 1 | 0x48 | unknown | not set by the match writer | 0 | 0 |
| 2 | 0x4c | points | += this match's points | 450 | 120 |
| 3 | 0x50 | wins | +1 on a win | 1 | 0 |
| 4 | 0x54 | losses | +1 on a loss or disconnect | 0 | 2 |
| 5 | 0x58 | draws | +1 on a draw | 0 | 0 |
| 6 | 0x5c | type-3 losses | +1 on a loss with finish type 3 | 0 | 0 |
| 7 | 0x60 | current win streak | +1 on a win, else 0 | 1 | 0 |
| 8 | 0x64 | best win streak | max(best, current) | 1 | 0 |
| 9 | 0x68 | current loss streak | +1 on a loss, else 0 | 0 | 2 |
| 10 | 0x6c | worst loss streak | max(worst, current) | 0 | 2 |
| 11 | 0x70 | win rate ‰ | wins·1000 / (W+L+D); 1000 or 0 when no games | 1000 | 0 |
| 12 | 0x74 | disconnect rate ‰ (inferred) | (X−1)·1000 / (W+L+D+X−1), X = the player's disconnect counter, raised before the match | 0 | 0 |

### Board 10: title record, 32 × i32 (`CDWTitleStatsInfo`, reader 0xbdf88)

| Cols | Fields | Meaning |
| --- | --- | --- |
| 1 | 0x48 | unknown (as board 1) |
| 2 | 0x4c | title-match points |
| 3-12 | 0x50-0x74 | combined: the sum of the next two sets (streaks/rates recomputed) |
| 13-22 | 0x78-0x9c | set B, updated when the game type's flag `+0x43` is set (inferred: tag title matches) |
| 23-32 | 0xa0-0xc4 | set C, updated otherwise (inferred: singles title matches) |

Each set of ten is W, L, D, type-3 losses, current win streak, best win streak, current loss streak,
worst loss streak, win rate ‰, disconnect rate ‰ (same formulas as board 1; title disconnects come from
the second private-profile counter).

### Boards 19 and 23: belt prestige, 38 × i32 (writer 0xbec58, readers 0xbeda8 / 0xbf458)

| Cols | Field | Meaning (setters `LBYM 0xb8740..0xb8788`, values from `OMEN FUN_00017a18` cases 2/3) |
| --- | --- | --- |
| 1 | Flag (0x48) | `FUN_00016ae8` (inferred: belt identifier/flags) |
| 2 | Prestige (0x4c) | belt prestige, `belt+0x3c` |
| 3 | Match (0x50) | matches with the belt, `belt+0x30` |
| 4 | Move (0x54) | belt changes hands, `belt+0x2c` (inferred) |
| 5 | TitleDefend (0x58) | defences, `belt+0x2e` |
| 6-38 | championship name | 33 characters, **one i32 per character** (0x21 bytes, NUL padded) |

### Board 27: DNA, 256 × i32

Telemetry written at login (`WriteDna`, lobby task 0x31): game modes, AI, Create-a-Entrance, control
type, difficulty, rules, superstars and season counters (`tagDNA::AddMode/AddMatch/AddSS/AddAI/
AddControlType` in the main ELF). Never read back; store or ignore.

## How a match turns into stats (OMEN, confirmed)

Per player after the match (`FUN_00017a18` state 8):

- **Result** (`FUN_00016548` → `MatchDataCtrl::GetResultForRoster`): 1 win, 0 loss, 2 draw.
- **Quit/disconnect** (`FUN_00016718`, bit per player in `CGssSmack + 0x3cc`): counted as a loss,
  0 points.
- **No contest** (`FUN_000167c0`, finish type 0x13): 0 points, not a draw.
- **Points** (`FUN_00016f80` → `FUN_00008f80`): the player's in-match performance score (`+0xbc` of
  their match data). Computed during the match by the game (450 for the winner, 120 for the loser in
  the capture); the server never computes points.
- Anti-cheat (`CheckCheat::CheckSuperStarRank / CheckOnlineRecord`, main ELF 0x277038 / 0x277138) runs
  on each player's record before writing.
- Disconnect counters: the private profile is set to 1 before a match and cleared after a clean finish
  (see svr2007-services.md), feeding the disconnect-rate column.

## Rank

- **Leaderboard rank** is the server's `u64 rank` in each row. The ranking screen (`OME2 FUN_000065e0`)
  first reads the player's own row (`ReadStatsByID`), then opens the list at `own rank − 26`
  (`ReadRankingByRank(category, position + 1, 50)`, case 3/4), so the player appears mid-page; it pages
  in steps of 50 and shows the rank and rating of each row (`FUN_0003dc70`).
- **Superstar rank** (matchmaking, `OMEN COnlineMatchDataCtrl::SearchSession` 0x2db0) is a star level
  0-11 from the player's **points** (field 0x4c of their total record, or of the title record for
  title matches; `FUN_00003840`), thresholds at `OMEN 0x4d344`: 10 000, 40 000, 80 000, 135 000,
  195 000, 270 000, 360 000, 490 000, 660 000, 850 000, 1 000 000. The search sends
  `SetRank(myStars, min, max)` from the search filters; hosts put their stars in the session info.
- **Titles/belts** are client-side: created belts live on the memory card (`CBeltSaveDataReader`,
  `CCreateBelt*` in the main ELF) and `GetTitleHolder`/`SetTitleHolder` are local. The prestige boards
  only rank belt holders by prestige; nothing marks rank 1 as champion. A player without a belt deletes
  their prestige rows (`DeleteStats(0x15/0x1a)` → stats task 2 for each board of the group).

## What the server must do

| Area | Server | Client |
| --- | --- | --- |
| Points, wins, streaks, rates, prestige | store as written | computes all of it |
| Own record at login (boards 1, 10) | return the stored row | adds the next match to it |
| Leaderboards | rank by rating, highest first; return rank, name, columns | displays, pages around own rank |
| Belt holders | delete rows on task 2 | decides belt ownership |
| Superstar rank | nothing (derived from returned points) | stars from points |

## Server changes needed

1. ✅ *Done.* **Implement stats delete (service 4, task 2)**: args `u8, i32 board, u64 user` (0 = the caller;
   sender `LBYM 0x6e690`), one task per board of the category group. Delete that row. Today the server
   answers success without deleting, so a player who loses or gives up a belt stays on the prestige
   rankings.
2. ✅ *Done.* **Make `rank` the row's position** (unique, ties broken consistently) rather than a shared rank. The
   ranking screen jumps to `own rank − 26` and pages by position, so a shared rank (1, 2, 2, 4)
   offsets the page slightly when ties exist (inferred effect; DemonWare ranks were positions).
3. Kept: board 27 (DNA) is stored or keep it for curiosity; it is never read.
4. No aggregation, decay or season logic is required: nothing in the client expects it.
