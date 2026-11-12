# Beta diagnostics

Run the hosted beta with the optional diagnostics override:

```sh
docker compose -f compose.yaml -f compose.beta.yaml up -d --build angelware capture
```

The override enables debug application logs and a passive capture sidecar. Use
both Compose files for subsequent deployments so the debug/log-rotation settings
stay enabled. PostgreSQL does not need to restart. Capture restarts automatically
after host reboot, and a health check reports stopped/stale capture or low disk.
To make plain `docker compose` commands keep beta mode, set
`COMPOSE_FILE=compose.yaml:compose.beta.yaml` in that machine's `.env`.

## What is recorded

- Full IPv4 TCP packets on the auth/lobby port (3074 by default), including both
  request and response directions, with packet timestamps.
- Full UDP packets on the title discovery/NAT ports and relay range
  (3074/3075, 2273/2274, and 20000–20199 by default).
- Decrypted lobby task debug logs, reply sizes and processing/queue durations,
  and socket write durations, correlated by peer, user, service, task, slot,
  and sequence. Existing logs include adaptive decisions, room generations,
  relay mappings, drops, flow totals, and rewrite/key-establishment outcomes.
- Capture health, storage use, host load, and kernel UDP error/drop counters,
  sampled every 30 seconds. Capture-tool messages include segment rotation and
  capture totals/drop statistics when available from the capture tool.

Capture uses [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html)
with full snap length, five-minute/approximately 64 MiB segments and a
16 MiB capture buffer. The sidecar only has `NET_RAW`, has no Docker socket, and
uses a read-only container filesystem outside the capture mount and `/tmp`.
It does not change packet routing. Packet timestamps let an offline analyzer
measure incoming-to-forwarded time separately from client response time.

The server can only capture packets that reach it. Direct console-to-console
gameplay and the external DNAS authentication exchange do not traverse this
server. The sidecar does not capture the shared host's DNS, web, SSH, database,
or unrelated service ports. Noninitial IP fragments do not match a port filter;
this is a full-snap-length capture of matching packets, not a host-wide sniffer.

## Retention and access

Defaults keep up to **72 hours**, subject to an **8 GiB** packet budget, and aim
to preserve **5 GiB** of host free space. The supervisor prunes completed
segments every five seconds. The active segment is never deleted, so allow one
segment plus traffic arriving between sweeps beyond the nominal budget. Under
heavy use the time window will be shorter than 72 hours. Disk pressure removes
oldest completed captures first; if free space is still below the floor,
capture pauses and its health check fails until space is available.

Application logs rotate at 20 × 25 MB; capture logs at 5 × 10 MB, with Docker's
`local` driver. Their retention is size-based and can differ from packet
retention. These limits apply to new container logs; saved incident bundles
are separate and must be archived/deleted manually.

Override `ANGELWARE_CAPTURE_HOURS`, `ANGELWARE_CAPTURE_MIB`,
`ANGELWARE_CAPTURE_FREE_MIB` or
`ANGELWARE_CAPTURE_INTERFACE` in the hosted `.env` as needed. The filter follows
the configured game ports and whether BRO is enabled.

Full packets and debug task payloads can expose password hashes, tickets, room
keys, IP addresses, player names, messages, and other session material. Capture
files are mode 600 inside a mode-700 directory on the Docker-managed
`angelware_beta-captures` volume; incident bundles are
mode 600. Keep them on the server or transfer privately to trusted maintainers.
Do not commit or attach raw bundles to public issues. No `.env`, database dump,
or recovered key file is included by the bundle helper.

## When a tester reports a problem

Ask for the time **with timezone**, player/account names, who hosted, the game
stage, and what each player saw. Preserve the incident promptly before rotation:

```sh
scripts/beta-bundle \
  --since 2026-11-12T15:35:00-06:00 \
  --until 2026-11-12T15:45:00-06:00 \
  --label ready-up-delay
```

With no times it selects the last 30 minutes. The private `.tar.gz` goes into
ignored `work/beta-bundles/`, with logs, overlapping PCAP segments, safe runtime
settings/image/revision metadata, capture status, and resource counters.
Segments include surrounding traffic from other sessions; a snapshot of the
live segment can end with a partial final packet, which offline readers can
discard. Collect a few minutes before the failure and after recovery; include
the whole sign-in/room-join sequence for peer-key/route analysis when possible.
The helper reports the number of matching capture segments. It requires the
running beta stack and local Docker access on the hosted machine.

```sh
docker compose -f compose.yaml -f compose.beta.yaml ps
docker compose -f compose.yaml -f compose.beta.yaml logs --tail 10 capture
```

Classic PCAP output works with Wireshark and the repository's
`tools/svr_capture.py`, `tools/svr_recover.py`, and
`tools/svr_relay_health.py`. TCP auth/ticket recovery still requires the relevant
authentication material; packet capture does not automatically decrypt all
protocols. Keep any derived plaintexts and keys private too.

To stop diagnostics without stopping the game server:

```sh
docker compose -f compose.yaml -f compose.beta.yaml stop capture
```

This stops new packets; existing captures continue to occupy disk. Recreate the
game service with the base Compose file to return to its configured log level
and logging driver. Neither action changes DNS or firewall rules.
