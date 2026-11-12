# SvR 2007 lobby services: tasks, results, stats and ranked play

Reference for implementing the lobby service gateway beyond what `internal/lobby` does today. Addresses
are offsets into the decompressed `LBYM` overlay (see svr2007-analysis.md, "Addresses").
**Confirmed** = read from the decompiled code; **inferred** = reasoned from names, captures or DemonWare
conventions and still worth checking against the game.

## Shared reply envelope

Every task reply (gateway message type 1) is a typed bit buffer:

```
u8 slot, u8 seq          echo the request
u32 error                0 = success
u8 taskID                echo of the request's task id (confirmed: every result parser switches on it)
u32 count                only for tasks that return results
results...               count items, layout per task below
```

The `u8` after the error is the **task id**, not a result count (confirmed for services 4, 5, 6, 9 and 12:
the parsers accept only specific values: matchmaking 1/4/5/6, mailbox 1/5, friends 5/7/16/17/19, stats
3/4/5/6, title utilities 1/2/4). Replies for tasks without results can stop after it.

> angelware today: matchmaking always sends `1` (works because 1 is accepted), and the generic reply
> sends `0` (taken as "no results"). Stats reads should echo `3`..`6` with `count = 0` until leaderboards
> exist.

## Service 6: mailbox and notifications (confirmed)

Polled about once a second. The game keeps a local queue of notifications. When the queue is empty it
fetches up to 20 (`FUN_0000ef50(…, 0, 0x14, 1, 1)` → task 1), dispatches each to a game callback
(`FUN_0001a3b8`), then acknowledges it by id (`FUN_0000eeb8` → task 4). Senders `0x69d68..0x6a198`;
lobby tasks 0x2c-0x2f (`FUN_00024bd0`, modes 0-3).

| Task | Args | Result | Meaning |
| --- | --- | --- | --- |
| 1 | u8, u32 offset, u32 count (20), bool, bool | messages | Fetch notifications |
| 4 | u8, u64 messageID | none | Acknowledge/delete one |
| 5 | u8, u32, u32, bool, bool | messages | Fetch variant (same layout as 1) |
| 6 | u8, u64 messageID, bool | none | Mark one (inferred: read/unread) |

**Result** (`FUN_0006a6d8`): `u32 error, u8 taskID (1 or 5), u32 count`, then `count` messages.

**Server push**: a gateway frame of message type **2** carries exactly one message in the same
encoding (`FUN_0006ad48` → `FUN_0006a8e8`), appended to the same queue (duplicates by message id are
dropped). This lets the server deliver friend requests, invites and messages instantly.

### Message encoding (`FUN_0006a8e8`, factory `FUN_000c74c0`)

```
u32 type                               selects the class (registered at 0x661a0..0x69c24)
common:   u64 ?, u64 messageID, u32 ?, bool ?          (base 0x76f08; messageID is acked by task 4)
class A:  common + u64 fromUserID, string fromName (≤63)          (0x6ca70)
class B:  common + u64 userID, string name, u64 userID2, string name2   (0x6c3f0)
```

| Type | Class layout | Game callback (`ILobbyCallBack` slot) |
| --- | --- | --- |
| 1 | A + u16 + blob | OnFriendPropose (friend request) |
| 2 | A | OnFriendProposeAccept |
| 3 | A | OnFriendProposeReject |
| 4 | A | OnFriendProposeCancel |
| 5 | A + blob + u16 + blob | OnInviteSession: the second part becomes a `CInviteInfo` (session id/key for the join) |
| 6 | A + blob + u16 + blob | OnInviteSessionAccept |
| 7 | A + blob + u16 + blob | OnInviteSessionReject |
| 8 | A + blob | OnFriendMessage(player, data, length): the text of SendFriendMessage |
| 9 | A + blob | OnFriendOnline |
| 10 | A + blob | OnFriendOffline |
| 11 | A + blob | OnBlockUser |
| 12 | A + blob | OnUnblockUser |
| 13-39 | B/C variants | DemonWare generic types; the game ignores them |

The callback mapping is confirmed from the switch in `FUN_0001a3b8` and the interceptor vtable at
`0xd2468` (`CLobbyCallBackIntercepter`). The meaning of the u16/blob extras on types 1 and 5-7 is inferred.

## Service 9: friends, blocking, messages, invites (confirmed)

Senders `0x60a90..0x61920`; lobby tasks 0x15-0x21 through `FUN_00024080`.

| Task | Game API (lobby task) | Args | Result |
| --- | --- | --- | --- |
| 1 | ProposeFriend (0x15) | u8, u64 user, blob, u32 | none |
| 13 | WithdrawProposalFriend (0x16) | u8, u64 user | none |
| 2 | AcceptProposeFriend (0x17) | u8, u64 user | none |
| 3 | RejectProposeFriend (0x18) | u8, u64 user | none |
| 4 | RemoveFriend (0x19) | u8, u64 user | none |
| 19 | LoadFriendProposeList (0x1a) | u8 | list of `u64 user, string name` |
| 5 | LoadFriendList (0x1b) | u8 | list of `u64 user, string name, bool online` |
| 6 | SetBlockUser (0x1c) | u8, u64 user, u8 level | none |
| 7 | LoadBlockUserList (0x1d) | u8 | list of `u64 user, string name, u8 level` (0, 1, 2 → game levels 1, 2, 3) |
| 12 | SendFriendMessage (0x1e) | u8, u64 user, u32, blob data, u32 | none |
| 8 | InviteGameSession (0x1f) | u8, u64 user, blob, u32, blob, u32 | none (inferred: session id + key) |
| 9 | AcceptInvitation (0x20) | u8, u64 user | none |
| 10 | RejectInvitation (0x21) | u8, u64 user | none |
| 14 | (unused) | u8, u64, u8 | |
| 15 | (unused) | u8, u8, string | inferred: look up a user by name |
| 16, 17, 18 | (unused) | u8 / u8 / u8, u8 | lists (parser accepts 16, 17) |

List results (`FUN_000619e8`, element readers `0x62628`, `0x62180`, `0x61cf8`) use the envelope with
`taskID` and `count`. Server side: persist friendships, pending requests and blocks; for each state
change also queue a service-6 message to the other player (types 1-4, 8-12) and push it if they are
online. Online status = has an open gateway connection.

## Service 8: profiles

| Task | Game API (lobby task, mode) | Args | Result |
| --- | --- | --- | --- |
| 1 | CreateProfile (0x0e, 0) | u8, public profile | none |
| 2 | read public profile (0x12, 1) | u8, u64 user | `u64 user, i32, i32, blob[48]` |
| 3 | ReadPrivateProfileInfo (0x13, 2) | u8 | `u64 user, i32 ×4` |
| 4 | update public profile (0x10, 3) | u8, public profile | none (confirmed: same object as create) |
| 5 | SetPrivateProfileInfo (0x11, 4) | u8, i32 ×4 | none |
| 6 | DeleteProfile (0x0f, 5) | u8 | none |
| 7 | profile exists (0x14, 6) | u8, u64 user | `bool exists` (`0x6cc60`) |

Private profile fields, in order (setters at 0xb97e8..0xb9820, confirmed): **TotalDisconnect,
TitleDisconnect, TitleSingleDisconnect, TitleTagDisconnect**. The game sets TotalDisconnect to 1
before a match and back to 0 after a clean finish (captured), so a player who quits keeps the
increment. The Title* counters cover title (belt) matches. The public profile's `i32, i32,
blob[48]` has no named accessors; captured values were all zero (inferred: unused or set later).

> angelware today: tasks 1, 2, 3, 5, 6 are implemented. 4 should update the public profile like 1;
> 7 should answer `bool` (currently "no results", which the game tolerates).

## Service 4: stats and leaderboards

### Tasks (senders `0x6e2c8..0x6ecb8`, game modes in `FUN_0002a218`)

| Task | Mode | Args | Result |
| --- | --- | --- | --- |
| 1 | 0 write | u8, u8 flag, i32 board, u64 (0), then the row | none |
| 2 | 1 delete | u8, i32 board, u64 user | none |
| 3 | 2 read by user | u8, i32 board, u64 user | rows |
| 4 | 3 read several users | u8, i32 board, u32 n, n × u64 user | rows (inferred: friends board) |
| 5 | 5 read around user | u8, i32 board, u64 user, u64 0, i64 50 | rows (confirmed from the caller in `FUN_0002a218`) |
| 6 | 4 read (other) | u8, u64, object | rows |
| 5 | 6 read by rank | u8, i32 board, u64 0, u64 start position, i64 50 | rows |
| 7, 9 | | multiple boards in one task | none |
| 8 | | u8, blob, u32 | |

Result (`FUN_0006ef98`): envelope with taskID; tasks 3-6 then carry `u32 count`, **`u32 total rows on
the board`** (`0x6f6e0`, `GetReadStatsTotalEntries`; only parsed when count > 0) and the rows (list
deserializer `0xbf778`, at most 50).

**Row read** (`0x6f328` plus the board's columns): `u64 user, i64 rating, u64 rank, string name (≤63)`,
then the board's extra columns. Column readers: `0xbd108` 12 × i32 (board 1), `0xbdf88` 32 × i32
(board 10), `0xbeda8`/`0xbf458` 6 × i32 (boards 19/23), `0xbcba0` none (rating-only boards). The
columns the game writes for a board are exactly what it reads back, so angelware returns stored rows
unchanged. angelware serves tasks 3, 4 and 5; task 6 returns no rows.
**Row write**: `i64 rating`, then the board's extra columns.

### Boards

The game writes in groups (category tables at `0xce0c0..0xce128`), mapping categories to boards in
`FUN_0002a108`:

| Boards | Categories | Class | Extra columns |
| --- | --- | --- | --- |
| 1 | 1, 2 | Total (`CDWTotalStatsInfo`) | **12 × i32** (the overall record) |
| 2-9 | 3-10 | Total | none: rating only |
| 10 | 11, 12 | Title (`CDWTitleStatsInfo`) | **32 × i32** |
| 11-18 | 13-20 | Title | none |
| 19 | 21, 22 | Single prestige (`CDWSinglePrestigeStatsInfo`) | 6 × i32: Flag, Prestige, Match, Move, TitleDefend, + one derived from the championship name (inferred) |
| 20-22 | 23-25 | Single prestige | none |
| 23 | 26, 27 | Tag prestige (`CDWTagPrestigeStatsInfo`) | same 6 × i32 as 19 |
| 24-26 | 28-30 | Tag prestige | none |
| 27 | DNA | `WriteDna` (lobby task 0x31, flag 1) | ~250 × i32 gameplay telemetry (`tagDNA`: modes, AI, CAE, control type, difficulty, rules, superstars, season) |

Captured after one match (2026-11-11): both players wrote boards 1-9. Board 1 from the host had
columns 3, 8 and 9 set to 1 (the other player's were all 0); the host's board 3 rating was 1. The
column meanings of board 1 are not named in the overlay (inferred: wins/losses/match counts by type;
compare more captures). At login the game reads boards 1 and 10 for the player (their record and title
stats) and writes board 27.

**Server behaviour**: store each row per (user, board) as written (angelware does this). Reads return
the stored rows; `rank` is the row's position on that board ordered by rating, highest first. Prestige
and title boards (10, 19, 23) hold the online championship belts (`COnlineCommon::GetTitleBelt`,
`CCreateBeltTitleMatch` prestige in the main ELF).

## Ranked matches and search filters

**Query** (DemonWare object `0x26ce8`, serializer `0x26db8`, filled by OMEN
`COnlineMatchDataCtrl::SearchSession` 0x2db0 from a `CSearchCondition`), all i32:

| # | Field | Source | Quick Match |
| --- | --- | --- | --- |
| 1 | type: 1/2 = ranked flag of the search, 3 = mode 1 | condition[2] == 1 | 1 |
| 2 | max results | | 50 |
| 3, 4 | 0, mode (nothing follows when mode ≠ 0) | | 0, 0 |
| 5, 6 | match type low/high | rule (OMEN 0x8658/0x8760); any = [0, 85] | 0, 85 |
| 7-9 | rank self, min, max | stars from points (`CSuperstarRank`), menu window (default 0..10) | 0, 0, 10 |
| 10, 11 | entrance low/high | yes/no/any = [1,1]/[0,0]/[0,1] (`IncEntranceExist`) | 0, 1 |
| 12, 13 | CAS low/high | same (`IncCasExist`) | 0, 1 |
| 14-18 | country, 0, 14, bool, condition[3] == 2 | not filtered | 0, 0, 14, 0, 0 |
| 19, 20 | country range low/high | `FUN_000044b0` | unbounded |

**Session info game fields** (serializer `0x27c90`, copy `0x276c0`), after the 7 DemonWare base fields
(blob address, id, key, slots public max/used, private max/used): 0 ranked, 1 name, 2 arena, 3 CAS, 4
country, 5-6 country range, 7 entrance, 8 manager, 9 match type, 10 PAL50, 11-13 rank self/min/max, 14 title
match, 15 session mode, 16 0, 17 i64 user, 18 ?, 19 superstar name blob[129], then sex, weight class, overall,
brand and CAS attributes.

**angelware's matching** (the original server's queries are unknown; each check pairs a query value with
the session field the game fills from the same setting): ranked flag equal (type 1 ↔ ranked 1, type 2 ↔
ranked 0); rank both ways (host stars in the searcher's window and the searcher's stars in the host's);
match type in range; entrance and CAS in range; country both ways; sessions with no free public slot are
hidden. Results are ordered by rank distance, then age, at most 20. Type 3 only checks free slots.

## Other services

| Service | Tasks seen | Notes |
| --- | --- | --- |
| 3 | 1-27 | No direct callers (reached through vtables); not used in captures. Args start `(u8, string)`, `(u8, u64, string)`, `(u8, u64, u64)`. Unknown purpose |
| 10 | 1-8 | Storage (`CDWStorageProcess`): upload, update, download, list by user/publisher (created wrestlers/replays, inferred). Args e.g. `(u8, bool, string, bool, blob)` |
| 11 | 1-6 | `(u8, u64)`, `(u8, u64, blob)`, … no game caller found; unused so far |
| 12 | 1-4 | Title utilities: 1 = check a string (lobby task 0x39; inferred profanity/name filter), 2 = `(u8, i16, i8, i8, i16, i16)` (inferred date), 3 = `(u32)`, 4 = `(u8)` (inferred server time). Result envelope accepts taskID 1, 2, 4 |

## Implementation priority

1. **Reply envelope fix**: echo the task id in every reply; send `count = 0` for list tasks with no data
   (stats 3-6, friends 5/7/19, mailbox 1/5).
2. **Mailbox (service 6) + push**: task 1 returns queued messages, task 4 deletes; push type-2 frames
   to online players. Needed by everything social.
3. **Friends (service 9)** with notifications: requests, accept/reject/cancel, remove, lists with online
   flag, block list, friend messages (type 8), online/offline (types 9/10).
4. **Invites**: InviteGameSession → type-5 message with the session id/key; accept/reject → types 6/7.
5. **Leaderboards**: stats reads (tasks 3, 4, 5, 6) from stored rows with rank by rating; board 1/10
   reads at login show the player's record.
6. **Profiles**: task 4 (update public), task 7 (exists → bool).
7. **Matchmaking filters**: honour the ranked flag, session mode and rank window in searches.
8. Later: storage (service 10), title utilities (service 12: accept every string), services 3 and 11 if the
   game ever calls them.
