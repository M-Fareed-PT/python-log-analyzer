#!/usr/bin/env python3
"""
log_analyzer.py
Medium-level log analysis tool (stdlib only).

Features:
- Auto-detects Apache/Nginx combined access logs and SSH/auth logs (simple heuristics).
- Parses lines and extracts timestamps, IPs, request paths, status codes, user names (for auth logs).
- Produces a JSON report with:
  - top N client IPs
  - top requested URLs (for web logs)
  - counts by status code class (2xx/3xx/4xx/5xx)
  - failed login attempts and suspected brute-force IPs
  - time-series hits per minute (sampled)
- Simple "suspicious" rules:
  - IP with >= --bf-threshold failed auth attempts is flagged
  - IP with many 4xx/5xx in short timespan can be flagged
- Usage examples in README below.

Note: Intended for **lab / analysis**. Do NOT use for real-time production monitoring.
"""

from __future__ import annotations
import re
import argparse
import json
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Optional, Tuple, Dict, List

# ---------------------------
# Regular expressions
# ---------------------------

# Apache/Nginx combined log (simplified)
RE_COMBINED = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s'           # IP
    r'(?P<ident>\S+)\s(?P<auth>\S+)\s'
    r'\[(?P<ts>[^\]]+)\]\s'                        # [day/month/year:time zone]
    r'"(?P<method>\S+)\s(?P<path>\S+)(?:\sHTTP/\d\.\d)?"\s'
    r'(?P<status>\d{3})\s(?P<size>\d+|-)\s'
    r'"(?P<referrer>[^"]*)"\s"(?P<ua>[^"]*)"'
)

# Common syslog timestamp formats like: "Nov  6 12:34:56"
RE_SYSLOG_TS = re.compile(r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})')

# SSHD / auth log line simple match for failed login
RE_SSHD = re.compile(
    r'(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?(?:sshd|ssh).*?(?P<type>Failed|Invalid|Accepted|authentication failure).*?(?:user\s(?P<user>\S+))?.*?(?:from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?',
    re.IGNORECASE
)

# ---------------------------
# Helpers
# ---------------------------

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

def parse_combined_ts(ts_str: str, year_hint: Optional[int] = None) -> Optional[datetime]:
    # format: 10/Oct/2000:13:55:36 -0700
    try:
        # remove timezone for simplicity (we could parse offset if needed)
        dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt
    except Exception:
        return None

def parse_syslog_ts(ts_str: str, year_hint: Optional[int] = None) -> Optional[datetime]:
    m = RE_SYSLOG_TS.search(ts_str)
    if not m:
        return None
    month = MONTHS.get(m.group('month'), 1)
    day = int(m.group('day'))
    hour = int(m.group('hour')); minute = int(m.group('min')); sec = int(m.group('sec'))
    year = year_hint or datetime.utcnow().year
    try:
        return datetime(year, month, day, hour, minute, sec)
    except Exception:
        return None

# ---------------------------
# Parser functions
# ---------------------------

def parse_line(line: str, year_hint: Optional[int] = None) -> Tuple[str, Dict]:
    """
    Try to parse a line and return (type, data)
    type in: 'access', 'auth', 'unknown'
    data contains extracted fields depending on type.
    """
    line = line.rstrip("\n")
    m = RE_COMBINED.match(line)
    if m:
        d = m.groupdict()
        ts = parse_combined_ts(d.get('ts', ''), year_hint=year_hint)
        return 'access', {
            'ip': d.get('ip'),
            'ts': ts.isoformat() if ts else None,
            'method': d.get('method'),
            'path': d.get('path'),
            'status': int(d.get('status')) if d.get('status') and d.get('status').isdigit() else None,
            'ua': d.get('ua'),
            'referrer': d.get('referrer')
        }
    m2 = RE_SSHD.search(line)
    if m2:
        gd = m2.groupdict()
        ts = parse_syslog_ts(gd.get('ts', ''), year_hint=year_hint)
        return 'auth', {
            'ip': gd.get('ip'),
            'ts': ts.isoformat() if ts else None,
            'event': gd.get('type'),
            'user': gd.get('user')
        }
    # fallback heuristics: look for "Failed password" or "authentication failure"
    if 'Failed password' in line or 'authentication failure' in line or 'Invalid user' in line:
        # try to grab ip with naive regex
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        ip = ip_match.group(1) if ip_match else None
        ts = parse_syslog_ts(line, year_hint=year_hint)
        return 'auth', {
            'ip': ip,
            'ts': ts.isoformat() if ts else None,
            'event': 'Failed',
            'user': None
        }
    return 'unknown', {'raw': line}

# ---------------------------
# Analysis engine
# ---------------------------

def analyze(lines: List[str], bf_threshold: int = 5, year_hint: Optional[int] = None) -> Dict:
    stats = {
        'total_lines': 0,
        'access_count': 0,
        'auth_count': 0,
        'unknown_count': 0,
        'top_ips': Counter(),
        'top_paths': Counter(),
        'status_classes': Counter(),  # e.g. 2xx,4xx
        'failed_auths': Counter(),    # ip -> count
        'auth_events': [],            # list of auth events
        'time_series_minute': Counter(),  # minute buckets
    }

    # sliding windows for heuristic detection (basic)
    recent_4xx = defaultdict(lambda: deque(maxlen=50))  # ip -> deque of timestamps (seconds)
    for line in lines:
        stats['total_lines'] += 1
        kind, data = parse_line(line, year_hint=year_hint)
        if kind == 'access':
            stats['access_count'] += 1
            ip = data.get('ip')
            if ip:
                stats['top_ips'][ip] += 1
            path = data.get('path') or "-"
            stats['top_paths'][path] += 1
            status = data.get('status')
            if status:
                cls = f"{status // 100}xx"
                stats['status_classes'][cls] += 1
                if cls in ('4xx', '5xx') and ip:
                    # record for short-window spikes
                    t = data.get('ts')
                    if t:
                        try:
                            ts_dt = datetime.fromisoformat(t)
                            recent_4xx[ip].append(ts_dt.timestamp())
                        except Exception:
                            pass
            # time series minute bucket
            t = data.get('ts')
            if t:
                try:
                    dt = datetime.fromisoformat(t)
                    minute = dt.replace(second=0, microsecond=0).isoformat()
                    stats['time_series_minute'][minute] += 1
                except Exception:
                    pass

        elif kind == 'auth':
            stats['auth_count'] += 1
            ip = data.get('ip') or 'unknown'
            stats['top_ips'][ip] += 1
            ev = {
                'ip': ip,
                'ts': data.get('ts'),
                'event': data.get('event'),
                'user': data.get('user')
            }
            stats['auth_events'].append(ev)
            # count failed auths
            evt_type = (data.get('event') or '').lower()
            if 'fail' in evt_type or 'invalid' in evt_type:
                stats['failed_auths'][ip] += 1
        else:
            stats['unknown_count'] += 1
            # maybe extract IPs loosely
            ipm = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if ipm:
                stats['top_ips'][ipm.group(1)] += 1

    # post-process: find suspected brute-force IPs
    suspected_bf = []
    for ip, cnt in stats['failed_auths'].items():
        if cnt >= bf_threshold:
            suspected_bf.append({'ip': ip, 'failed_attempts': cnt})

    # 4xx/5xx burst detection: if > X 4xx in short time
    bursty_ips = []
    for ip, dq in recent_4xx.items():
        if len(dq) >= 5:
            # measure timespan between earliest and latest in deque
            if dq and (dq[-1] - dq[0]) <= 60:  # 60 seconds
                bursty_ips.append({'ip': ip, '4xx_count_recent': len(dq), 'span_seconds': int(dq[-1] - dq[0])})

    # top lists limited
    top_ips = stats['top_ips'].most_common(20)
    top_paths = stats['top_paths'].most_common(20)
    status_classes = dict(stats['status_classes'])
    time_series = dict(sorted(stats['time_series_minute'].items()))

    report = {
        'summary': {
            'total_lines': stats['total_lines'],
            'access_count': stats['access_count'],
            'auth_count': stats['auth_count'],
            'unknown_count': stats['unknown_count'],
            'top_ip_count': len(stats['top_ips'])
        },
        'top_ips': [{'ip': ip, 'count': c} for ip, c in top_ips],
        'top_paths': [{'path': p, 'count': c} for p, c in top_paths],
        'status_classes': status_classes,
        'failed_auths': [{'ip': ip, 'count': c} for ip, c in stats['failed_auths'].items()],
        'suspected_bruteforce': suspected_bf,
        'bursty_4xx_ips': bursty_ips,
        'time_series_minute': time_series,
        'auth_events_sample': stats['auth_events'][:200]  # limit size
    }
    return report

# ---------------------------
# CLI and glue
# ---------------------------

def detect_file_type(sample_lines: List[str]) -> str:
    """
    Heuristic to guess the log type.
    Returns: 'access', 'auth', or 'unknown'
    """
    access_hits = 0
    auth_hits = 0
    for ln in sample_lines:
        if RE_COMBINED.search(ln):
            access_hits += 1
        if 'sshd' in ln or 'Failed password' in ln or 'authentication failure' in ln:
            auth_hits += 1
    if access_hits >= auth_hits and access_hits > 0:
        return 'access'
    if auth_hits > 0:
        return 'auth'
    return 'unknown'

def load_file(path: str, max_sample: int = 5000) -> List[str]:
    with open(path, 'r', encoding='utf8', errors='ignore') as f:
        lines = f.readlines()
    return lines

def cli():
    p = argparse.ArgumentParser(description="Simple Log Analyzer (Apache/Nginx access + auth logs)")
    p.add_argument("--file", "-f", required=True, help="Path to log file")
    p.add_argument("--out", "-o", default="report.json", help="Write JSON report")
    p.add_argument("--bf-threshold", type=int, default=5, help="Failed-auth threshold to flag brute-force")
    p.add_argument("--year", type=int, default=None, help="Year hint for syslog timestamps (optional)")
    args = p.parse_args()

    lines = load_file(args.file)
    sample = lines[:200]
    ftype = detect_file_type(sample)
    print(f"[*] Loaded {len(lines)} lines. Heuristic type: {ftype}")

    report = analyze(lines, bf_threshold=args.bf_threshold, year_hint=args.year)
    with open(args.out, 'w', encoding='utf8') as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Report written to {args.out}")

if __name__ == "__main__":
    cli()
