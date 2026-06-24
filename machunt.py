#!/usr/bin/env python3
"""
machunt - a macOS-native threat hunter.

Most security tooling ignores macOS. machunt audits the places malware actually
hides on a Mac - LaunchAgents/Daemons, login items, cron, shell start-up files,
and running processes - flags the suspicious ones, and maps each finding to a
MITRE ATT&CK technique. Read-only: it never changes anything.

    machunt hunt            # audit this Mac
    machunt hunt --demo     # also scan a bundled fixture with a planted threat
    machunt hunt --demo-only  # scan ONLY the bundled fixture (safe, isolated)
    machunt hunt --json     # machine-readable output

Built for the Mac mini it runs on. No dependencies beyond `rich` (optional).
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

HOME = Path.home()

# command/path patterns that don't belong in a persistence mechanism
SUSPICIOUS = [
    (r"curl\b.*\|\s*(sh|bash|zsh)", "downloads & pipes to a shell"),
    (r"wget\b.*\|\s*(sh|bash|zsh)", "downloads & pipes to a shell"),
    (r"base64\s+-{0,2}d", "base64-decoded payload"),
    (r"\b(python3?|perl|ruby)\b.*-c\b", "inline interpreter one-liner"),
    (r"\beval\b", "eval of dynamic code"),
    (r"osascript\b.*-e\b", "inline AppleScript"),
    (r"/dev/tcp/", "raw reverse-shell socket"),
    (r"\bn(c|cat)\b.*-e", "netcat with -e (reverse shell)"),
    (r"(^|\s)(/private)?/tmp/|/Users/Shared/|/var/tmp/", "runs from a world-writable dir"),
]
SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    severity: str
    attck: str
    title: str
    detail: str
    path: str = ""


def _cmd_of(plist: dict) -> str:
    if "ProgramArguments" in plist and isinstance(plist["ProgramArguments"], list):
        return " ".join(str(a) for a in plist["ProgramArguments"])
    return str(plist.get("Program", ""))


def _scan_cmd(cmd: str) -> list[str]:
    return [why for pat, why in SUSPICIOUS if re.search(pat, cmd, re.IGNORECASE)]


# --------------------------------------------------------------------------- #
def hunt_launch(dirs: list[Path]) -> list[Finding]:
    out = []
    for d in dirs:
        if not d.exists():
            continue
        daemon = "Daemon" in d.name
        attck = "T1543.004 (Launch Daemon)" if daemon else "T1543.001 (Launch Agent)"
        for f in sorted(d.glob("*.plist")):
            try:
                pl = plistlib.loads(f.read_bytes())
            except Exception:
                continue
            cmd = _cmd_of(pl)
            label = str(pl.get("Label", f.stem))
            hits = _scan_cmd(cmd)
            masquerade = (label.startswith("com.apple.")
                          and "/System/" not in cmd and "/usr/libexec/" not in cmd
                          and "/Library/Apple" not in cmd and cmd)
            if masquerade:
                hits.append("Apple-style label but non-Apple binary (masquerade)")
            if hits:
                sev = "high" if any(k in " ".join(hits) for k in
                                    ("shell", "reverse", "masquerade", "base64")) else "medium"
                out.append(Finding(sev, attck, f"persistence: {label}",
                                   f"{cmd}  →  {'; '.join(hits)}", str(f)))
            elif pl.get("RunAtLoad") and pl.get("KeepAlive"):
                out.append(Finding("info", attck, f"persistence: {label}",
                                   f"auto-runs & restarts: {cmd}", str(f)))
    return out


def hunt_shell_rc() -> list[Finding]:
    out = []
    for name in (".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".profile"):
        f = HOME / name
        if not f.exists():
            continue
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            for why in _scan_cmd(s):
                out.append(Finding("high", "T1546.004 (Shell startup)",
                                   f"{name}:{i}", f"{s[:90]}  →  {why}", str(f)))
    return out


def hunt_cron() -> list[Finding]:
    out = []
    try:
        cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        cron = ""
    for line in cron.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            why = _scan_cmd(s)
            out.append(Finding("medium" if why else "info", "T1053.003 (Cron)",
                               "crontab entry", s[:90] + ("  →  " + "; ".join(why) if why else "")))
    return out


def hunt_login_items() -> list[Finding]:
    try:
        r = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True, timeout=8)
        items = [x.strip() for x in r.stdout.split(",") if x.strip()]
    except Exception:
        items = []
    return [Finding("info", "T1547.015 (Login Items)", f"login item: {it}",
                    "runs at user login") for it in items]


def hunt_processes() -> list[Finding]:
    out = []
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True,
                            text=True, timeout=6).stdout
    except Exception:
        return out
    for line in ps.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, comm = line.partition(" ")
        for why in _scan_cmd(comm):
            out.append(Finding("high", "T1059 (Execution)", f"pid {pid}",
                               f"{comm}  →  {why}"))
    return out


# --------------------------------------------------------------------------- #
def run(demo: bool, demo_only: bool = False) -> list[Finding]:
    if demo_only:                       # isolated: scan ONLY the bundled fixture
        f = hunt_launch([Path(__file__).parent / "demo/LaunchAgents"])
        return sorted(f, key=lambda x: SEV_ORDER[x.severity], reverse=True)
    launch_dirs = [HOME / "Library/LaunchAgents",
                   Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
    if demo:
        launch_dirs.append(Path(__file__).parent / "demo/LaunchAgents")
    findings = (hunt_launch(launch_dirs) + hunt_shell_rc() + hunt_cron()
                + hunt_login_items() + hunt_processes())
    return sorted(findings, key=lambda f: SEV_ORDER[f.severity], reverse=True)


def report(findings: list[Finding]):
    counts = {s: sum(f.severity == s for f in findings) for s in ("high", "medium", "low", "info")}
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        con = Console()
        con.print(Panel.fit(
            f"[bold]machunt[/] · macOS threat hunt    "
            f"[red]high {counts['high']}[/]  [yellow]medium {counts['medium']}[/]  "
            f"[blue]info {counts['info']}[/]    {len(findings)} findings",
            border_style="cyan"))
        t = Table(header_style="bold")
        for c in ("sev", "MITRE ATT&CK", "finding", "detail"):
            t.add_column(c)
        colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        for f in findings:
            t.add_row(f"[{colors[f.severity]}]{f.severity.upper()}[/]",
                      f.attck, f.title, f.detail[:70])
        con.print(t)
        if counts["high"]:
            con.print("[red bold][!] high-severity persistence found. Investigate the paths above.[/]")
    except ImportError:
        for f in findings:
            print(f"[{f.severity.upper():6}] {f.attck:28} {f.title} :: {f.detail}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="machunt",
                                description="Read-only macOS persistence & anomaly hunter (MITRE ATT&CK).")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hunt", help="audit this Mac")
    h.add_argument("--demo", action="store_true", help="also scan the bundled threat fixture")
    h.add_argument("--demo-only", action="store_true", help="scan ONLY the bundled fixture (isolated)")
    h.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    if args.cmd == "hunt":
        if sys.platform != "darwin" and not (args.demo or args.demo_only):
            print("note: live hunting targets macOS; use --demo elsewhere.", file=sys.stderr)
        findings = run(args.demo or args.demo_only, demo_only=args.demo_only)
        if args.json:
            print(json.dumps([asdict(f) for f in findings], indent=2))
        else:
            report(findings)
        return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
