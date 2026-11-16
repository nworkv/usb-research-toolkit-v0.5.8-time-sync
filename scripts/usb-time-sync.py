#!/usr/bin/env python3
"""Check or synchronize a remote target OS clock over SSH.

The machine running this utility is the time source. The remote target can be
Linux or Windows with OpenSSH Server enabled. No USB device is touched.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import subprocess
import time
from pathlib import Path


def run_ssh(args, remote_command: str, timeout: int = 15) -> str:
    cmd = ["ssh", "-p", str(args.port), "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=8"]
    if args.identity:
        cmd += ["-i", args.identity]
    cmd += [f"{args.user}@{args.host}", remote_command]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or f"ssh exit {p.returncode}").strip())
    return p.stdout.strip()


def remote_now_ms(args) -> int:
    if args.target_os == "linux":
        command = "date -u +%s%3N"
    else:
        ps = "[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()"
        command = 'powershell.exe -NoProfile -NonInteractive -Command "' + ps + '"'
    raw = run_ssh(args, command)
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    raise RuntimeError(f"cannot parse remote UTC milliseconds from: {raw!r}")


def set_remote(args, epoch_ms: int) -> str:
    if args.target_os == "linux":
        command = f"sudo -n date -u -s @{epoch_ms / 1000:.3f}"
    else:
        ps = ("$d=[DateTimeOffset]::FromUnixTimeMilliseconds(" + str(epoch_ms) +
              ").UtcDateTime; Set-Date -Date $d | Out-Null; "
              "[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()")
        command = 'powershell.exe -NoProfile -NonInteractive -Command "' + ps + '"'
    return run_ssh(args, command, timeout=20)


def main() -> int:
    ap = argparse.ArgumentParser(description="Check/synchronize target OS UTC clock over SSH")
    ap.add_argument("--host", required=True, help="target OS hostname/IP")
    ap.add_argument("--user", required=True, help="SSH username")
    ap.add_argument("--target-os", required=True, choices=("linux", "windows"))
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--identity", help="SSH private-key path")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="measure clock drift without changing time")
    mode.add_argument("--sync", action="store_true", help="set target clock from this machine's UTC clock")
    ap.add_argument("--max-drift-ms", type=int, default=2000,
                    help="check-mode threshold for PASS (default: 2000 ms)")
    ap.add_argument("--out-dir", default="runs/time-sync", help="directory for JSON/TXT report")
    ap.add_argument("--confirm-time-change", action="store_true",
                    help="required with --sync; explicitly authorizes changing target system time")
    args = ap.parse_args()
    if not 1 <= args.port <= 65535 or args.max_drift_ms < 0:
        ap.error("port must be 1..65535 and max-drift-ms must be >= 0")
    if args.sync and not args.confirm_time_change:
        ap.error("--sync requires --confirm-time-change")
    report = {
        "tool": "usb-time-sync", "target": f"{args.user}@{args.host}",
        "target_os": args.target_os, "mode": "sync" if args.sync else "check",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "local system UTC clock",
        "warning": "Clock changes can affect logs, certificates, scheduled jobs and time-sensitive services."
    }
    try:
        source_before = time.time_ns() // 1_000_000
        target_before = remote_now_ms(args)
        report["before"] = {
            "source_utc": dt.datetime.fromtimestamp(source_before/1000, dt.timezone.utc).isoformat(),
            "target_utc": dt.datetime.fromtimestamp(target_before/1000, dt.timezone.utc).isoformat(),
            "target_minus_source_ms": target_before-source_before
        }
        if args.sync:
            source_set = time.time_ns() // 1_000_000
            report["set_command_output"] = set_remote(args, source_set)
            target_after = remote_now_ms(args)
            source_after = time.time_ns() // 1_000_000
            drift = target_after-source_after
            report["after"] = {
                "source_utc": dt.datetime.fromtimestamp(source_after/1000, dt.timezone.utc).isoformat(),
                "target_utc": dt.datetime.fromtimestamp(target_after/1000, dt.timezone.utc).isoformat(),
                "target_minus_source_ms": drift
            }
            report["status"] = "SYNCED" if abs(drift) <= max(args.max_drift_ms, 5000) else "SYNCED_BUT_DRIFT_REMAINS"
        else:
            drift = target_before-source_before
            report["status"] = "PASS" if abs(drift) <= args.max_drift_ms else "DRIFT_EXCEEDS_THRESHOLD"
    except Exception as exc:
        report["status"] = "ERROR"
        report["error"] = str(exc)
    report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out/"time-sync.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    lines = ["USB LAB — TARGET OS TIME SYNCHRONIZATION", f"Target: {report['target']} ({args.target_os})",
             f"Mode: {report['mode']}", f"Status: {report['status']}"]
    if "before" in report:
        lines.append(f"Before drift (target - source): {report['before']['target_minus_source_ms']} ms")
    if "after" in report:
        lines.append(f"After drift (target - source): {report['after']['target_minus_source_ms']} ms")
    if "error" in report:
        lines.append(f"Error: {report['error']}")
    lines += ["", "See time-sync.json for UTC timestamps and full details."]
    (out/"time-sync.txt").write_text("\n".join(lines)+"\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if report["status"] in ("PASS", "SYNCED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
