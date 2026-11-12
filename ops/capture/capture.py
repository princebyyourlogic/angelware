"""Private, bounded full-packet diagnostics for the AngelWare game ports."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path('/captures')
PATTERN = re.compile(r'packets-\d{8}T\d{6}Z-[0-9a-f]+_\d+_(\d{14})\.pcap$')


def emit(event, **fields):
    print(json.dumps({'time': dt.datetime.now(dt.timezone.utc).isoformat(),
                      'event': event, **fields}), flush=True)


def number(env, default, low, high):
    value = int(os.environ.get(env, default))
    if not low <= value <= high:
        raise ValueError(f'{env} must be in {low}..{high}')
    return value


def capture_filter():
    port = number('ANGELWARE_PORT', 3074, 1, 65535)
    ports = {port, number('ANGELWARE_STUN_ALT_PORT', 3075, 1, 65535)}
    if os.environ.get('ANGELWARE_BRO', 'on') != 'off':
        ports.update({number('ANGELWARE_BRO_PORT', 2273, 1, 65535),
                      number('ANGELWARE_BRO_ALT_PORT', 2274, 1, 65535)})
    lo, hi = map(int, os.environ.get('ANGELWARE_RELAY_PORTS', '20000-20199').split('-'))
    if not 1 <= lo <= hi <= 65535:
        raise ValueError('invalid ANGELWARE_RELAY_PORTS')
    udp = ' or '.join(f'port {p}' for p in sorted(ports))
    return f'ip and (tcp port {port} or (udp and ({udp} or portrange {lo}-{hi})))'


def files(root):
    result = []
    for path in root.glob('packets-*.pcap'):
        if PATTERN.fullmatch(path.name) and not path.is_symlink():
            try:
                result.append((path, path.stat()))
            except FileNotFoundError:  # capture rotation / another snapshot
                pass
    return sorted(result, key=lambda item: (item[1].st_mtime_ns, item[0].name))


def prune(root, max_age, max_bytes, min_free, now=None, active=None, disk_free=None, entries=None):
    """Delete only completed capture segments; never touch unrelated files."""
    now = time.time() if now is None else now
    disk_free = (lambda: shutil.disk_usage(root).free) if disk_free is None else disk_free
    entries = files(root) if entries is None else entries
    total = sum(stat.st_size for _, stat in entries)
    deleted = []
    for path, stat in entries:
        if path == active:
            continue
        if now-stat.st_mtime <= max_age and total <= max_bytes and disk_free() >= min_free:
            continue
        try:
            path.unlink()
            total -= stat.st_size
            deleted.append(path.name)
        except FileNotFoundError:
            pass
    return {'files': len(entries)-len(deleted), 'bytes': total,
            'deleted': len(deleted), 'free_bytes': disk_free()}


def system_metrics():
    result = {'load': os.getloadavg()}
    try:
        lines = Path('/proc/net/snmp').read_text().splitlines()
        for a, b in zip(lines, lines[1:]):
            if a.startswith('Udp:') and b.startswith('Udp:'):
                result['udp'] = dict(zip(a.split()[1:], map(int, b.split()[1:])))
                break
    except (OSError, ValueError):
        pass
    return result


def write_status(root, **status):
    tmp = root / '.status.tmp'
    tmp.write_text(json.dumps({'checked': time.time(), **status})+'\n')
    tmp.replace(root / 'status.json')


def stop(child):
    if child is not None and child.poll() is None:
        child.send_signal(signal.SIGINT)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def run(root):
    os.umask(0o077)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    max_age = number('ANGELWARE_CAPTURE_HOURS', 72, 1, 720)*3600
    max_bytes = number('ANGELWARE_CAPTURE_MIB', 8192, 64, 1048576)*1024**2
    min_free = number('ANGELWARE_CAPTURE_FREE_MIB', 5120, 64, 1048576)*1024**2
    rotate = number('ANGELWARE_CAPTURE_SECONDS', 300, 1, 3600)
    segment_kib = number('ANGELWARE_CAPTURE_SEGMENT_KIB', 65536, 1, 1048576)
    if segment_kib*1024 > max_bytes:
        raise ValueError('capture segment must fit within the disk budget')
    interface = os.environ.get('ANGELWARE_CAPTURE_INTERFACE', 'any')
    filter_text = capture_filter()
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    version = subprocess.check_output(['dumpcap', '--version'], text=True).splitlines()[0]
    emit('capture configured', filter=filter_text, interface=interface, hours=max_age/3600,
         budget_bytes=max_bytes, free_floor_bytes=min_free, version=version)
    child = None
    threads = []
    last_report = 0

    def tool_output(pipe):
        for line in pipe:
            text = line.strip()
            if text:
                emit('capture tool', text=text[:2000])
        pipe.close()

    try:
        while not done.is_set():
            running = child is not None and child.poll() is None
            if child is not None and not running:
                raise RuntimeError(f'dumpcap exited unexpectedly: {child.returncode}')
            entries = files(root)
            # dumpcap continuously rotates its own files, without a capture restart.
            active = entries[-1][0] if running and entries else None
            # Use this same snapshot for pruning: a newly opened segment must
            # never enter a second directory scan with an outdated active name.
            usage = prune(root, max_age, max_bytes, min_free, active=active, entries=entries)
            if usage['free_bytes'] < min_free:
                stop(child)
                child = None
                usage = prune(root, max_age, max_bytes, min_free)
                state = 'paused-low-disk'
            else:
                if child is None:
                    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                    prefix = root / f'packets-{stamp}-{os.urandom(4).hex()}.pcap'
                    child = subprocess.Popen(['dumpcap', '-i', interface, '-p', '-s', '0',
                                              '-B', '16', '-P', '-q', '-f', filter_text,
                                              '-b', f'duration:{rotate}', '-b', f'filesize:{segment_kib}',
                                              '-b', 'printname:stdout', '-w', str(prefix)],
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    thread = threading.Thread(target=tool_output, args=(child.stdout,), daemon=True)
                    thread.start()
                    threads = [t for t in threads if t.is_alive()] + [thread]
                state = 'capturing'
            write_status(root, state=state, pid=child.pid if child else None,
                         filter=filter_text, interface=interface, **usage)
            if time.monotonic()-last_report >= 30 or usage['deleted']:
                emit('capture health', state=state, **usage, **system_metrics())
                last_report = time.monotonic()
            done.wait(5)
    finally:
        stop(child)
        for thread in threads:
            thread.join(timeout=2)
        write_status(root, state='stopped', pid=None)


def select_files(root, since, until):
    selected = []
    for path, stat in files(root):
        stamp = PATTERN.fullmatch(path.name).group(1)
        start = dt.datetime.strptime(stamp, '%Y%m%d%H%M%S').replace(tzinfo=dt.timezone.utc).timestamp()
        if start <= until and stat.st_mtime >= since:
            selected.append(path)
    return selected


def export(root, since, until):
    # Tar limits each live file to its size at snapshot time. Its last packet may
    # be incomplete; earlier records remain readable. Closed segments are intact.
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
        for path in select_files(root, since, until):
            try:
                with path.open('rb') as stream:
                    info = tarfile.TarInfo(path.name)
                    stat = os.fstat(stream.fileno())
                    info.size, info.mtime, info.mode = stat.st_size, int(stat.st_mtime), 0o600
                    archive.addfile(info, stream)
            except FileNotFoundError:
                continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=['run', 'health', 'export'], default='run')
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--since', type=float)
    parser.add_argument('--until', type=float)
    args = parser.parse_args()
    if args.command == 'run':
        run(args.root)
    elif args.command == 'health':
        status = json.loads((args.root / 'status.json').read_text())
        if status['state'] != 'capturing' or time.time()-status['checked'] > 20:
            raise SystemExit(1)
        os.kill(status['pid'], 0)
        if not files(args.root):
            raise SystemExit(1)
    else:
        if args.since is None or args.until is None or args.since > args.until:
            parser.error('export requires --since <= --until as Unix timestamps')
        export(args.root, args.since, args.until)


if __name__ == '__main__':
    main()
