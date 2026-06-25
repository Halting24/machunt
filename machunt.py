#!/usr/bin/env python3
"""
machunt - a macOS-native threat hunter, mapped to MITRE ATT&CK.

Most security tooling ignores macOS. machunt audits the places malware actually
hides on a Mac: LaunchAgents/Daemons, login items, cron, at jobs, shell startup
files (user and global), SSH keys and config, sudoers, configuration profiles,
browser extensions, kernel/system extensions, network listeners, code-signature
anomalies, recently-modified persistence binaries, and running processes.

Every finding is tagged to a MITRE ATT&CK technique. The tool is strictly
read-only and never writes to or modifies any system location.

Usage:
    machunt hunt                         # audit this Mac
    machunt hunt --demo                  # also scan bundled threat fixture
    machunt hunt --demo-only             # scan ONLY the fixture (isolated/safe)
    machunt hunt --json                  # machine-readable JSON output
    machunt hunt --sarif                 # SARIF 2.1 output for GitHub/VS Code
    machunt hunt --html report.html      # self-contained HTML report
    machunt hunt --snapshot base.json    # save baseline for later diff
    machunt hunt --baseline base.json    # show only new/changed since baseline
    machunt hunt --allowlist allow.txt   # suppress known-good labels/paths

Built for the Mac mini it runs on. Dependencies: stdlib + rich (optional for
colour output), pyyaml (optional, for loading extra rules from rules.yaml).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

HOME = Path.home()

# ---------------------------------------------------------------------------
# Rule engine: structured suspicious patterns.
# Each rule: (pattern, why, severity, attck)
# severity is used when this rule fires as the SOLE trigger on an item; callers
# may upgrade based on combinations.
# ---------------------------------------------------------------------------
RULES: list[tuple[str, str, str, str]] = [
    # T1059 - command and scripting interpreters
    (r"curl\b.*\|\s*(sh|bash|zsh)",        "downloads and pipes to a shell",           "high",   "T1059.004"),
    (r"wget\b.*\|\s*(sh|bash|zsh)",        "downloads and pipes to a shell",           "high",   "T1059.004"),
    (r"base64\s+-{0,2}d",                  "base64-decoded payload",                   "high",   "T1027"),
    (r"\b(python3?|perl|ruby)\b.*-c\b",    "inline interpreter one-liner",             "high",   "T1059"),
    (r"\beval\b",                          "eval of dynamic code",                     "medium", "T1059"),
    (r"osascript\b.*-e\b",                 "inline AppleScript execution",             "medium", "T1059.002"),
    (r"OSASCRIPT_ENABLE_JAVA",             "AppleScript JXA abuse flag",               "medium", "T1059.002"),

    # T1059 / network
    (r"/dev/tcp/",                         "raw reverse-shell TCP socket",             "high",   "T1059.004"),
    (r"\bn(c|cat)\b.*-e",                  "netcat with -e flag (reverse shell)",      "high",   "T1059.004"),
    (r"bash\s+-i\b",                       "interactive reverse shell",                "high",   "T1059.004"),

    # world-writable / staging directories
    (r"(^|\s)(/private)?/tmp/|/Users/Shared/|/var/tmp/",
                                           "runs from a world-writable directory",     "medium", "T1036.005"),

    # obfuscation / staging
    (r"\$\(.*base64",                      "command substitution with base64",         "high",   "T1027"),
    (r"\\x[0-9a-fA-F]{2}",                "hex-escaped bytes (obfuscation)",          "medium", "T1027"),
    (r"IEX\b|Invoke-Expression",           "PowerShell IEX (lateral tool)",            "medium", "T1059.001"),

    # file download helpers without piping (still worth flagging)
    (r"\bcurl\b.*-[oO]\s+/tmp/",          "curl writing to /tmp",                     "medium", "T1105"),
    (r"\bwget\b.*-[oO]\s+/tmp/",          "wget writing to /tmp",                     "medium", "T1105"),
]


def _extra_rules_from_yaml(path: Path) -> list[tuple[str, str, str, str]]:
    """Load additional rules from a YAML file if pyyaml is available."""
    try:
        import yaml
    except ImportError:
        return []
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text())
        out: list[tuple[str, str, str, str]] = []
        for r in (data or []):
            out.append((r["pattern"], r["why"], r.get("severity", "medium"), r.get("attck", "T1059")))
        return out
    except Exception:
        return []


_ACTIVE_RULES: list[tuple[str, str, str, str]] = list(RULES)


def _scan_cmd(cmd: str) -> list[tuple[str, str]]:
    """Return list of (why, attck) for all matching rules."""
    return [(why, attck) for pat, why, _sev, attck in _ACTIVE_RULES
            if re.search(pat, cmd, re.IGNORECASE)]


SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------------------
# Well-known-good allowlist: labels and path fragments that are known benign.
# Applied to suppress INFO-level noise; HIGH/MEDIUM findings are never suppressed.
# ---------------------------------------------------------------------------
DEFAULT_ALLOWLIST: set[str] = {
    "com.apple.",
    "com.docker.",
    "com.spotify.",
    "homebrew",
    "com.microsoft.",
    "com.google.",
    "com.adobe.",
    "com.dropbox.",
    "com.1password.",
    "com.jetbrains.",
    "com.sublimetext.",
    "org.pqrs.",
}

_USER_ALLOWLIST: set[str] = set()


def _is_allowlisted(label: str, path: str) -> bool:
    combined = (label + " " + path).lower()
    for token in (DEFAULT_ALLOWLIST | _USER_ALLOWLIST):
        if token.lower() in combined:
            return True
    return False


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str          # high / medium / low / info
    attck: str             # MITRE ATT&CK technique ID and name
    title: str             # short human-readable label
    detail: str            # details about the finding
    path: str = ""         # file or resource path
    fingerprint: str = ""  # stable hash for baseline diffing

    def __post_init__(self) -> None:
        if not self.fingerprint:
            raw = f"{self.attck}|{self.title}|{self.path}"
            self.fingerprint = hashlib.sha1(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _cmd_of(plist: dict) -> str:
    if "ProgramArguments" in plist and isinstance(plist["ProgramArguments"], list):
        return " ".join(str(a) for a in plist["ProgramArguments"])
    return str(plist.get("Program", ""))


def _run(cmd: list[str], timeout: int = 8) -> str:
    """Run a subprocess, return stdout, return '' on any failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _codesign_check(binary: str) -> Optional[str]:
    """Return a warning string if a Mach-O binary is unsigned or ad-hoc signed, else None.
    Script files (shell/Python/Perl/Ruby) are skipped - they cannot be code-signed
    and many legitimate Apple system scripts are unsigned by design."""
    if not binary:
        return None
    real_binary = binary.split()[0]
    if not Path(real_binary).exists():
        return None
    # Skip scripts by reading the shebang line
    try:
        with open(real_binary, "rb") as fh:
            magic = fh.read(4)
        # Mach-O magic: CE FA ED FE (32-bit LE), CF FA ED FE (64-bit LE), or fat
        mach_o_magic = {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                        b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbe"}
        if magic not in mach_o_magic:
            return None  # not a Mach-O binary; skip codesign check
    except Exception:
        return None
    try:
        r = subprocess.run(
            ["codesign", "--verify", "--verbose=2", real_binary],
            capture_output=True, text=True, timeout=6)
        err = r.stderr + r.stdout
    except Exception:
        return None
    if "code object is not signed" in err:
        return "binary is unsigned"
    if "adhoc" in err.lower():
        return "binary is ad-hoc signed"
    return None


def _quarantine_check(binary: str) -> Optional[str]:
    """Return a warning string if the binary has a quarantine xattr set, else None."""
    real_binary = binary.split()[0] if binary else ""
    if not real_binary or not Path(real_binary).exists():
        return None
    xattr_out = _run(["xattr", "-l", real_binary], timeout=5)
    if "com.apple.quarantine" in xattr_out:
        return "binary has com.apple.quarantine xattr (downloaded from internet)"
    return None


# ---------------------------------------------------------------------------
# Hunt modules
# ---------------------------------------------------------------------------

def hunt_launch(dirs: list[Path], apply_allowlist: bool = True) -> list[Finding]:
    """Scan LaunchAgent and LaunchDaemon directories (T1543.001 / T1543.004)."""
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
            cmd_first = cmd.split()[0] if cmd.split() else ""
            # Scan full command for behavioural patterns (curl|bash, eval, etc.)
            # but check world-writable-dir only against the binary itself.
            hits_full = _scan_cmd(cmd)
            hits_binary = _scan_cmd(cmd_first)
            # Merge: keep full-cmd hits except "world-writable" which is binary-only
            hits = []
            for why, attck_tag in hits_full:
                if "world-writable" in why:
                    continue  # will add back if binary is in a suspicious location
                hits.append((why, attck_tag))
            for why, attck_tag in hits_binary:
                if "world-writable" in why:
                    hits.append((why, attck_tag))
            reasons = [why for why, _ in hits]

            # com.apple.* masquerade detection: real Apple system daemons run from
            # /System/, /usr/, /sbin/, /bin/, /Library/Apple, or use short
            # unqualified names (resolved by launchd from system PATH).
            # Flag only when the binary path is a full absolute path outside
            # standard Apple locations, indicating a third-party binary using
            # an Apple-style label to blend in.
            masquerade = (
                label.startswith("com.apple.")
                and cmd_first.startswith("/")   # only flag absolute paths
                and not any(cmd_first.startswith(p) for p in (
                    "/System/", "/usr/", "/sbin/", "/bin/",
                    "/Library/Apple", "/private/var/db/", "/private/var/folders/",
                ))
            )
            if masquerade:
                reasons.append("Apple-style label on non-Apple binary (masquerade)")

            # code-signature anomalies
            sig_warn = _codesign_check(cmd)
            if sig_warn and cmd:
                reasons.append(sig_warn)

            # quarantine xattr
            quar_warn = _quarantine_check(cmd)
            if quar_warn:
                reasons.append(quar_warn)

            if reasons:
                sev = "high" if any(
                    k in " ".join(reasons)
                    for k in ("shell", "reverse", "masquerade", "base64")
                ) else "medium"
                out.append(Finding(sev, attck, f"persistence: {label}",
                                   f"{cmd}  ->  {'; '.join(reasons)}", str(f)))
            elif pl.get("RunAtLoad") and pl.get("KeepAlive"):
                if apply_allowlist and _is_allowlisted(label, cmd):
                    continue
                out.append(Finding("info", attck, f"persistence: {label}",
                                   f"auto-runs and restarts: {cmd}", str(f)))
    return out


def hunt_shell_rc() -> list[Finding]:
    """Scan user shell startup files for suspicious commands (T1546.004)."""
    out = []
    for name in (".zshrc", ".zprofile", ".zlogin", ".bash_profile", ".bashrc", ".profile"):
        f = HOME / name
        if not f.exists():
            continue
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            hits = _scan_cmd(s)
            for why, attck in hits:
                out.append(Finding("high", f"T1546.004 (Shell startup) / {attck}",
                                   f"{name}:{i}", f"{s[:120]}  ->  {why}", str(f)))
    return out


def hunt_global_shell() -> list[Finding]:
    """Scan global shell config files for suspicious commands (T1546.004)."""
    # Known-good patterns in /etc shell files that are set by Apple itself.
    GLOBAL_SHELL_BENIGN = re.compile(
        r"path_helper|/usr/libexec/path_helper|manpath_helper"
    )
    out = []
    targets = [
        Path("/etc/zshenv"), Path("/etc/zshrc"), Path("/etc/zprofile"),
        Path("/etc/profile"), Path("/etc/bashrc"), Path("/etc/bash.bashrc"),
    ]
    for f in targets:
        if not f.exists():
            continue
        try:
            text = f.read_text(errors="ignore")
        except PermissionError:
            out.append(Finding("info", "T1546.004 (Shell startup)",
                               f"global shell file: {f.name}",
                               "file exists but is not readable (permission denied)", str(f)))
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if GLOBAL_SHELL_BENIGN.search(s):
                continue
            hits = _scan_cmd(s)
            for why, attck in hits:
                out.append(Finding("high", f"T1546.004 (Global shell) / {attck}",
                                   f"{f}:{i}", f"{s[:120]}  ->  {why}", str(f)))
    return out


def hunt_cron() -> list[Finding]:
    """Scan user crontab (T1053.003)."""
    out = []
    cron = _run(["crontab", "-l"], timeout=5)
    for line in cron.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        hits = _scan_cmd(s)
        reasons = [why for why, _ in hits]
        sev = "medium" if reasons else "info"
        detail = s[:120] + ("  ->  " + "; ".join(reasons) if reasons else "")
        out.append(Finding(sev, "T1053.003 (Cron)", "crontab entry", detail))
    return out


def hunt_at_jobs() -> list[Finding]:
    """Look for at(1) jobs and /etc/periodic scripts (T1037, T1053)."""
    out = []
    # at jobs via atq
    atq = _run(["atq"], timeout=5)
    for line in atq.splitlines():
        line = line.strip()
        if not line:
            continue
        job_id = line.split()[0] if line.split() else "?"
        out.append(Finding("medium", "T1053 (Scheduled Task)",
                           f"at job #{job_id}",
                           f"at job queued: {line[:120]}"))

    # /etc/periodic scripts
    for period in ("15min", "daily", "weekly", "monthly"):
        d = Path(f"/etc/periodic/{period}")
        if not d.exists():
            continue
        for scr in sorted(d.iterdir()):
            if scr.is_file():
                try:
                    text = scr.read_text(errors="ignore")
                except PermissionError:
                    text = ""
                hits = _scan_cmd(text)
                reasons = [why for why, _ in hits]
                sev = "medium" if reasons else "info"
                out.append(Finding(sev, "T1037 (Boot/Logon Init Script)",
                                   f"periodic/{period}/{scr.name}",
                                   "; ".join(reasons) if reasons else "periodic maintenance script",
                                   str(scr)))
    # login/logout hooks in com.apple.loginwindow
    loginwindow_pl = Path("/var/root/Library/Preferences/com.apple.loginwindow.plist")
    # also accessible via defaults
    hooks_out = _run(["defaults", "read", "com.apple.loginwindow", "LoginHook"], timeout=5)
    if hooks_out.strip() and "does not exist" not in hooks_out:
        out.append(Finding("high", "T1037.001 (Logon Script - Mac)",
                           "LoginHook",
                           f"command runs at every login: {hooks_out.strip()[:120]}"))
    logout_out = _run(["defaults", "read", "com.apple.loginwindow", "LogoutHook"], timeout=5)
    if logout_out.strip() and "does not exist" not in logout_out:
        out.append(Finding("medium", "T1037.001 (Logon Script - Mac)",
                           "LogoutHook",
                           f"command runs at every logout: {logout_out.strip()[:120]}"))
    return out


def hunt_login_items() -> list[Finding]:
    """Enumerate login items via System Events (T1547.015)."""
    out = []
    r = _run(["osascript", "-e",
              'tell application "System Events" to get the name of every login item'],
             timeout=8)
    items = [x.strip() for x in r.split(",") if x.strip()]
    for it in items:
        if _is_allowlisted(it, it):
            continue
        out.append(Finding("info", "T1547.015 (Login Items)", f"login item: {it}",
                           "runs at user login"))
    return out


def hunt_ssh() -> list[Finding]:
    """Check SSH authorized_keys and SSH client config for anomalies (T1098.004)."""
    out = []
    ssh_dir = HOME / ".ssh"
    if not ssh_dir.exists():
        return out

    # authorized_keys
    for ak_name in ("authorized_keys", "authorized_keys2"):
        ak = ssh_dir / ak_name
        if not ak.exists():
            continue
        try:
            lines = ak.read_text(errors="ignore").splitlines()
        except PermissionError:
            continue
        count = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
        out.append(Finding("medium", "T1098.004 (Account Manipulation - SSH)",
                           f"authorized_keys ({count} entries)",
                           f"{count} authorized public key(s) can log in as {HOME.name}",
                           str(ak)))
        # flag any forced-command or no-* restrictions
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if re.search(r'command="[^"]*"', s):
                forced = re.search(r'command="([^"]*)"', s)
                cmd_val = forced.group(1)[:80] if forced else ""
                out.append(Finding("medium", "T1098.004",
                                   f"authorized_keys:{i} forced-command",
                                   f"key has forced command: {cmd_val}", str(ak)))

    # SSH client config
    ssh_config = ssh_dir / "config"
    if ssh_config.exists():
        try:
            text = ssh_config.read_text(errors="ignore")
        except PermissionError:
            text = ""
        # ProxyCommand can be abused to tunnel traffic
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if re.search(r"^\s*ProxyCommand\b", s, re.IGNORECASE):
                hits = _scan_cmd(s)
                reasons = [why for why, _ in hits]
                sev = "high" if reasons else "info"
                out.append(Finding(sev, "T1098.004 / T1572 (Protocol Tunneling)",
                                   f"~/.ssh/config:{i} ProxyCommand",
                                   s[:120] + ("  ->  " + "; ".join(reasons) if reasons else ""),
                                   str(ssh_config)))
    return out


def hunt_sudoers() -> list[Finding]:
    """Check sudoers and sudoers.d for NOPASSWD rules or wildcards (T1548.003)."""
    out = []
    targets = [Path("/etc/sudoers")]
    d = Path("/etc/sudoers.d")
    if d.exists():
        try:
            targets += sorted(d.iterdir())
        except PermissionError:
            out.append(Finding("info", "T1548.003 (Sudo and Sudo Caching)",
                               "/etc/sudoers.d",
                               "sudoers.d directory exists but is not readable"))

    for fp in targets:
        try:
            text = fp.read_text(errors="ignore")
        except PermissionError:
            out.append(Finding("info", "T1548.003 (Sudo and Sudo Caching)",
                               str(fp),
                               "file exists but permission denied (run as root to inspect)"))
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "NOPASSWD" in s.upper():
                is_wild = "ALL" in s.upper() and "NOPASSWD: ALL" in s.upper()
                sev = "high" if is_wild else "medium"
                out.append(Finding(sev, "T1548.003 (Sudo and Sudo Caching)",
                                   f"{fp.name}:{i} NOPASSWD rule",
                                   s[:120], str(fp)))
    return out


def hunt_config_profiles() -> list[Finding]:
    """Enumerate installed configuration profiles (T1553 / MDM abuse)."""
    out = []
    if not shutil.which("profiles"):
        return out
    text = _run(["profiles", "-C"], timeout=10)
    if not text.strip():
        return out
    # count profile entries
    count = len(re.findall(r"profileIdentifier|com\.apple", text))
    if text.strip():
        out.append(Finding("info",
                           "T1553 (Subvert Trust Controls) / MDM",
                           f"config profiles installed: {max(count, 1)}",
                           "use 'profiles -C -v' for full details (may contain MDM or network settings)"))
    # flag any profile that contains a proxy or certificate key
    if re.search(r"ProxyServer|PayloadType.*Certificate|com\.apple\.security", text, re.IGNORECASE):
        out.append(Finding("medium",
                           "T1553.004 (Install Root Certificate)",
                           "config profile: certificate or proxy payload detected",
                           "profile may install trusted CA or redirect traffic"))
    return out


def hunt_tcc_hints() -> list[Finding]:
    """Read-only TCC hints: list what apps have full disk access or accessibility (T1548)."""
    out = []
    # We can check the TCC database at a read-only path (user TCC only, not root)
    tcc_db = HOME / "Library/Application Support/com.apple.TCC/TCC.db"
    if tcc_db.exists():
        # Use sqlite3 (stdlib) read-only; URI mode with immutable flag
        try:
            import sqlite3
            uri = f"file:{tcc_db}?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True, timeout=5)
            cur = con.cursor()
            # kTCCServiceAccessibility and kTCCServiceSystemPolicyAllFiles are the big two
            for service, label in (
                ("kTCCServiceAccessibility", "Accessibility"),
                ("kTCCServiceSystemPolicyAllFiles", "Full Disk Access"),
                ("kTCCServiceScreenCapture", "Screen Recording"),
            ):
                rows = cur.execute(
                    "SELECT client FROM access WHERE service=? AND allowed=1", (service,)
                ).fetchall()
                for (client,) in rows:
                    if not _is_allowlisted(client, client):
                        out.append(Finding("info",
                                           "T1548 (Abuse Elevation Control Mechanism)",
                                           f"TCC: {label} granted",
                                           f"bundle/binary: {client}"))
            con.close()
        except Exception:
            # Locked or no permission - note it
            out.append(Finding("info", "T1548",
                               "TCC database",
                               "TCC.db found but not readable (SIP protection or locked)"))
    return out


def hunt_browser_extensions() -> list[Finding]:
    """Enumerate installed browser extensions (T1176)."""
    out = []
    targets: list[tuple[str, Path]] = [
        ("Chrome", HOME / "Library/Application Support/Google/Chrome/Default/Extensions"),
        ("Chrome (Profile 1)", HOME / "Library/Application Support/Google/Chrome/Profile 1/Extensions"),
        ("Brave", HOME / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
        ("Arc", HOME / "Library/Application Support/Arc/User Data/Default/Extensions"),
        ("Firefox", HOME / "Library/Application Support/Firefox/Profiles"),
        ("Safari", HOME / "Library/Safari/Extensions"),
    ]
    for browser, ext_dir in targets:
        if not ext_dir.exists():
            continue
        if browser == "Firefox":
            # Firefox stores extensions in profiles
            for profile_dir in ext_dir.iterdir():
                exts_json = profile_dir / "extensions.json"
                if exts_json.exists():
                    try:
                        data = json.loads(exts_json.read_text(errors="ignore"))
                        addons = data.get("addons", [])
                        for addon in addons:
                            name = addon.get("defaultLocale", {}).get("name", addon.get("id", "?"))
                            active = addon.get("active", False)
                            if active:
                                out.append(Finding("info", "T1176 (Browser Extensions)",
                                                   f"Firefox extension: {name}",
                                                   f"id: {addon.get('id', '?')}  active: {active}"))
                    except Exception:
                        pass
        elif browser == "Safari":
            try:
                for ext_path in sorted(ext_dir.glob("*.safariextz")) if ext_dir.is_dir() else []:
                    out.append(Finding("info", "T1176 (Browser Extensions)",
                                       f"Safari extension: {ext_path.stem}", str(ext_path)))
                # Also check the plist
                exts_plist = HOME / "Library/Safari/Extensions/Extensions.plist"
                if exts_plist.exists():
                    try:
                        pl = plistlib.loads(exts_plist.read_bytes())
                        for ext in pl.get("Installed Extensions", []):
                            name = ext.get("Archive File Name", ext.get("Bundle Directory Name", "?"))
                            out.append(Finding("info", "T1176 (Browser Extensions)",
                                               f"Safari extension: {name}",
                                               f"enabled: {ext.get('Enabled', '?')}"))
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            # Chromium-family: each subdirectory is an extension ID
            try:
                ext_ids = [d for d in sorted(ext_dir.iterdir()) if d.is_dir()]
                for ext_id_dir in ext_ids:
                    # find latest version subfolder
                    versions = sorted(ext_id_dir.iterdir(), reverse=True) if ext_id_dir.is_dir() else []
                    manifest = None
                    for v in versions:
                        mf = v / "manifest.json"
                        if mf.exists():
                            try:
                                manifest = json.loads(mf.read_text(errors="ignore"))
                            except Exception:
                                pass
                            break
                    if manifest:
                        name = manifest.get("name", ext_id_dir.name)
                        perms = manifest.get("permissions", [])
                        risky = [p for p in perms if p in (
                            "tabs", "webRequest", "webRequestBlocking", "cookies",
                            "history", "bookmarks", "clipboardRead", "nativeMessaging",
                            "<all_urls>",
                        )]
                        sev = "medium" if risky else "info"
                        detail = f"id: {ext_id_dir.name}"
                        if risky:
                            detail += f"  ->  risky permissions: {', '.join(risky)}"
                        out.append(Finding(sev, "T1176 (Browser Extensions)",
                                           f"{browser} extension: {name}",
                                           detail))
            except Exception:
                pass
    return out


def hunt_kernel_extensions() -> list[Finding]:
    """Enumerate kernel and system extensions (T1547.006)."""
    out = []
    # System extensions (modern macOS)
    sext_out = _run(["systemextensionsctl", "list"], timeout=10)
    if sext_out.strip():
        for line in sext_out.splitlines():
            s = line.strip()
            # Skip header lines, section banners, and the column-name row
            if (not s or s.startswith("---") or s.startswith("enabled")
                    or s.startswith("(") or s[0].isdigit()):
                continue
            # Real entries contain a bundle ID like 'com.foo.bar' or 'io.foo.bar'
            m = re.search(r"([a-z][a-z0-9_-]+\.[a-z][a-z0-9_.-]+)\s+\(", s)
            if not m:
                continue
            bundle_id = m.group(1)
            state = "[activated enabled]" if "[activated enabled]" in s else s.split()[-1] if s.split() else "?"
            sev = "info" if "[activated enabled]" in s else "low"
            if _is_allowlisted(bundle_id, bundle_id):
                continue
            out.append(Finding(sev, "T1547.006 (Kernel Modules and Extensions)",
                               f"system extension: {bundle_id}",
                               f"state: {state}  line: {s[:100]}"))

    # Legacy kexts via kmutil (macOS 11+)
    kext_out = _run(["kmutil", "showloaded", "--show", "loaded-and-all-boot-managed"],
                    timeout=15)
    if kext_out.strip():
        for line in kext_out.splitlines():
            s = line.strip()
            # skip header lines
            if not s or s.startswith("index") or s.startswith("OSKext"):
                continue
            # kext lines typically contain a bundle ID
            m = re.search(r"com\.\S+", s)
            if m:
                kext_id = m.group()
                if _is_allowlisted(kext_id, kext_id):
                    continue
                out.append(Finding("info", "T1547.006 (Kernel Modules and Extensions)",
                                   f"kext: {kext_id}",
                                   s[:120]))
    return out


def hunt_network_listeners() -> list[Finding]:
    """Find TCP listeners and flag those running from unusual paths (T1049 / T1071)."""
    out = []
    # Try lsof first (most informative), fall back to netstat
    lsof_out = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=15)
    if not lsof_out.strip():
        # netstat fallback (less process detail)
        ns_out = _run(["netstat", "-an", "-p", "tcp"], timeout=10)
        for line in ns_out.splitlines():
            if "LISTEN" in line:
                out.append(Finding("info", "T1049 (System Network Connections Discovery)",
                                   "TCP listener", line.strip()[:120]))
        return out

    seen: set[str] = set()
    for line in lsof_out.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        proc_name = parts[0]
        pid = parts[1]
        addr_port = parts[8]
        # try to get the full path from /proc equivalent on macOS
        proc_path = _run(["lsof", "-p", pid, "-a", "-d", "txt", "-Fn"], timeout=8)
        binary_path = ""
        for pl in proc_path.splitlines():
            if pl.startswith("n") and "/" in pl:
                binary_path = pl[1:]
                break

        key = f"{proc_name}:{addr_port}"
        if key in seen:
            continue
        seen.add(key)

        # Flag listeners on non-standard paths
        suspicious_path = binary_path and not any(
            binary_path.startswith(p) for p in (
                "/Applications/", "/System/", "/usr/", "/Library/",
                "/private/var/", "/opt/homebrew/", "/usr/local/",
            )
        )
        # Flag listeners on high-risk ports that are not in standard locations
        high_risk_port = re.search(r":(\d+)$", addr_port)
        port_num = int(high_risk_port.group(1)) if high_risk_port else 0
        odd_port = port_num < 1024 and port_num not in (80, 443, 22, 53, 8080, 8443, 631, 5900)

        detail = f"pid {pid}  addr {addr_port}"
        if binary_path:
            detail += f"  binary: {binary_path[:80]}"

        if suspicious_path:
            out.append(Finding("high", "T1071 (Application Layer Protocol)",
                               f"listener from odd path: {proc_name}",
                               detail + "  ->  running from non-standard location"))
        elif odd_port and binary_path:
            out.append(Finding("medium", "T1049 (System Network Connections Discovery)",
                               f"listener on low port: {proc_name}:{port_num}",
                               detail))
        else:
            if _is_allowlisted(proc_name, binary_path or proc_name):
                continue
            out.append(Finding("info", "T1049 (System Network Connections Discovery)",
                               f"TCP listener: {proc_name}",
                               detail))
    return out


def hunt_recently_modified(dirs: list[Path], days: int = 3) -> list[Finding]:
    """Flag executables in persistence directories modified in the last N days (T1543)."""
    out = []
    cutoff = time.time() - (days * 86400)
    for d in dirs:
        if not d.exists():
            continue
        try:
            for f in sorted(d.iterdir()):
                if not f.is_file():
                    continue
                try:
                    mtime = f.stat().st_mtime
                except OSError:
                    continue
                if mtime >= cutoff:
                    age_h = (time.time() - mtime) / 3600
                    age_str = f"{age_h:.1f}h ago" if age_h < 48 else f"{age_h/24:.1f}d ago"
                    out.append(Finding("medium",
                                       "T1543 (Create or Modify System Process)",
                                       f"recently modified: {f.name}",
                                       f"modified {age_str}  path: {f}",
                                       str(f)))
        except PermissionError:
            pass
    return out


def hunt_processes() -> list[Finding]:
    """Scan running processes for suspicious command lines (T1059)."""
    out = []
    ps = _run(["ps", "-axo", "pid=,comm="], timeout=8)
    for line in ps.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, comm = line.partition(" ")
        hits = _scan_cmd(comm)
        for why, attck in hits:
            out.append(Finding("high", f"T1059 (Execution) / {attck}",
                               f"pid {pid}",
                               f"{comm}  ->  {why}"))
    return out


# ---------------------------------------------------------------------------
# Baseline / diff support
# ---------------------------------------------------------------------------
def snapshot(findings: list[Finding]) -> dict:
    """Serialize findings to a baseline dict."""
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "1",
        "findings": [asdict(f) for f in findings],
    }


def diff_baseline(current: list[Finding], baseline_path: Path) -> list[Finding]:
    """Return only findings that are new or changed since the baseline."""
    try:
        base_data = json.loads(baseline_path.read_text())
        base_fps = {f["fingerprint"] for f in base_data.get("findings", [])}
    except Exception as e:
        print(f"[warn] could not load baseline: {e}", file=sys.stderr)
        return current
    return [f for f in current if f.fingerprint not in base_fps]


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
def report(findings: list[Finding], demo_mode: bool = False) -> None:
    """Print a rich (or plain) table to stdout."""
    counts = {s: sum(f.severity == s for f in findings) for s in ("high", "medium", "low", "info")}
    risk = (counts["high"] * 3 + counts["medium"] * 2 + counts["low"])
    if risk == 0:
        risk_str = "CLEAN"
    elif risk < 3:
        risk_str = "LOW RISK"
    elif risk < 8:
        risk_str = "MODERATE"
    else:
        risk_str = "ELEVATED"

    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        con = Console()
        header_parts = (
            f"[bold]machunt[/] - macOS threat hunt"
            + (f"  [dim](demo fixtures included)[/]" if demo_mode else "")
            + f"\n[red]HIGH {counts['high']}[/]  [yellow]MEDIUM {counts['medium']}[/]"
            + f"  [blue]LOW {counts['low']}[/]  [dim]INFO {counts['info']}[/]"
            + f"    {len(findings)} findings    risk: [bold]{risk_str}[/]"
        )
        con.print(Panel.fit(header_parts, border_style="cyan"))
        t = Table(header_style="bold", box=box.SIMPLE_HEAVY, show_lines=False)
        for c in ("sev", "MITRE ATT&CK", "finding", "detail", "path"):
            t.add_column(c, overflow="fold")
        colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        for f in findings:
            t.add_row(
                f"[{colors[f.severity]}]{f.severity.upper()}[/]",
                f.attck,
                f.title,
                f.detail[:80],
                (f.path[:60] if f.path else ""),
            )
        con.print(t)
        if counts["high"]:
            con.print("[red bold][!] high-severity persistence found. Investigate the paths above.[/]")
        elif counts["medium"]:
            con.print("[yellow][*] medium-severity findings detected. Review recommended.[/]")
        else:
            con.print(f"[green][ok] overall risk: {risk_str}[/]")
    except ImportError:
        print(f"machunt - macOS threat hunt  HIGH {counts['high']}  MEDIUM {counts['medium']}  "
              f"INFO {counts['info']}  risk: {risk_str}")
        for f in findings:
            print(f"[{f.severity.upper():6}] {f.attck:35} {f.title} :: {f.detail[:80]}")
        if counts["high"]:
            print("[!] high-severity persistence found.")


def to_sarif(findings: list[Finding]) -> dict:
    """Return a SARIF 2.1.0 document for the given findings."""
    rules: list[dict] = []
    seen_rule_ids: set[str] = set()
    results: list[dict] = []

    for f in findings:
        # derive a short rule id from the attck tag
        rule_id = re.sub(r"[^A-Za-z0-9._-]", "_", f.attck)[:64]
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.attck,
                "shortDescription": {"text": f.attck},
                "fullDescription": {"text": f.attck + " - machunt finding"},
                "defaultConfiguration": {
                    "level": {
                        "high": "error",
                        "medium": "warning",
                        "low": "note",
                        "info": "none",
                    }.get(f.severity, "none")
                },
            })
        artifact: dict = {}
        if f.path:
            artifact = {"artifactLocation": {"uri": Path(f.path).as_posix()}}
        results.append({
            "ruleId": rule_id,
            "level": {
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "none",
            }.get(f.severity, "none"),
            "message": {"text": f"{f.title}: {f.detail}"},
            "locations": [{"physicalLocation": {"artifactLocation": artifact.get("artifactLocation", {"uri": "unknown"})}}],
            "fingerprints": {"machunt/v1": f.fingerprint},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "machunt",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/Halting24/machunt",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def to_html(findings: list[Finding], out_path: Path) -> None:
    """Write a self-contained HTML report."""
    counts = {s: sum(f.severity == s for f in findings) for s in ("high", "medium", "low", "info")}
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    rows = ""
    sev_class = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low", "info": "sev-info"}
    for f in findings:
        rows += (
            f"<tr class='{sev_class[f.severity]}'>"
            f"<td>{f.severity.upper()}</td>"
            f"<td>{_h(f.attck)}</td>"
            f"<td>{_h(f.title)}</td>"
            f"<td>{_h(f.detail[:200])}</td>"
            f"<td><code>{_h(f.path[:100])}</code></td>"
            f"</tr>\n"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>machunt report - {now}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:2rem}}
h1{{color:#58a6ff}}
table{{border-collapse:collapse;width:100%;font-size:.88rem}}
th{{background:#161b22;color:#8b949e;text-align:left;padding:.5rem .75rem;border-bottom:1px solid #30363d}}
td{{padding:.4rem .75rem;border-bottom:1px solid #21262d;vertical-align:top}}
.sev-high td:first-child{{color:#f85149;font-weight:bold}}
.sev-medium td:first-child{{color:#e3b341;font-weight:bold}}
.sev-low td:first-child{{color:#79c0ff}}
.sev-info td:first-child{{color:#6e7681}}
.summary{{display:flex;gap:1.5rem;margin:.75rem 0 1.5rem;font-size:1.1rem}}
.badge{{padding:.25rem .75rem;border-radius:.4rem;font-weight:bold}}
.b-high{{background:#3d1b1b;color:#f85149}}
.b-med{{background:#2d2a18;color:#e3b341}}
.b-low{{background:#1b2636;color:#79c0ff}}
.b-info{{background:#1c2128;color:#8b949e}}
code{{background:#161b22;padding:.1rem .3rem;border-radius:.25rem;font-size:.85em}}
</style></head>
<body>
<h1>machunt - macOS Threat Hunt Report</h1>
<p>Generated: <b>{now}</b> | Host: <b>{_h(os.uname().nodename)}</b></p>
<div class="summary">
  <span class="badge b-high">HIGH {counts['high']}</span>
  <span class="badge b-med">MEDIUM {counts['medium']}</span>
  <span class="badge b-low">LOW {counts['low']}</span>
  <span class="badge b-info">INFO {counts['info']}</span>
  <span>| {len(findings)} total findings</span>
</div>
<table>
<thead><tr><th>Severity</th><th>MITRE ATT&amp;CK</th><th>Finding</th><th>Detail</th><th>Path</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<p style="color:#6e7681;font-size:.8rem;margin-top:2rem">
  Generated by <a href="https://github.com/Halting24/machunt" style="color:#58a6ff">machunt</a>.
  Read-only audit - no system changes were made.
</p>
</body></html>"""
    out_path.write_text(html, encoding="utf-8")


def _h(s: str) -> str:
    """Escape HTML special characters."""
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run(demo: bool, demo_only: bool = False) -> list[Finding]:
    """Run all hunt modules and return sorted findings."""
    if demo_only:
        # demo-only: no allowlist applied so benign INFO fixtures still show
        f = hunt_launch([Path(__file__).parent / "demo" / "LaunchAgents"],
                        apply_allowlist=False)
        return sorted(f, key=lambda x: SEV_ORDER[x.severity], reverse=True)

    demo_dir = Path(__file__).parent / "demo" / "LaunchAgents"
    launch_dirs = [
        HOME / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path("/System/Library/LaunchDaemons"),
    ]
    if demo:
        launch_dirs.append(demo_dir)

    findings: list[Finding] = []
    findings += hunt_launch(launch_dirs)
    findings += hunt_shell_rc()
    findings += hunt_global_shell()
    findings += hunt_cron()
    findings += hunt_at_jobs()
    findings += hunt_login_items()
    findings += hunt_ssh()
    findings += hunt_sudoers()
    findings += hunt_config_profiles()
    findings += hunt_tcc_hints()
    findings += hunt_browser_extensions()
    findings += hunt_kernel_extensions()
    findings += hunt_network_listeners()
    findings += hunt_recently_modified(launch_dirs, days=3)
    findings += hunt_processes()
    return sorted(findings, key=lambda f: SEV_ORDER[f.severity], reverse=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    # Load extra rules from rules.yaml if it exists in the tool directory
    rules_yaml = Path(__file__).parent / "rules.yaml"
    extra = _extra_rules_from_yaml(rules_yaml)
    if extra:
        _ACTIVE_RULES.extend(extra)

    p = argparse.ArgumentParser(
        prog="machunt",
        description="Read-only macOS persistence and anomaly hunter (MITRE ATT&CK).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hunt", help="audit this Mac")
    h.add_argument("--demo",      action="store_true", help="also scan bundled threat fixture")
    h.add_argument("--demo-only", action="store_true", help="scan ONLY the bundled fixture (isolated)")
    h.add_argument("--json",      action="store_true", help="machine-readable JSON to stdout")
    h.add_argument("--sarif",     action="store_true", help="SARIF 2.1 JSON to stdout")
    h.add_argument("--html",      metavar="FILE",      help="write self-contained HTML report to FILE")
    h.add_argument("--snapshot",  metavar="FILE",      help="save current findings to FILE for future diff")
    h.add_argument("--baseline",  metavar="FILE",      help="show only NEW findings vs FILE snapshot")
    h.add_argument("--allowlist", metavar="FILE",
                   help="text file of label/path tokens to suppress as INFO noise")
    args = p.parse_args(argv)

    if args.cmd != "hunt":
        p.print_help()
        return 1

    if sys.platform != "darwin" and not (args.demo or args.demo_only):
        print("note: live hunting targets macOS; use --demo or --demo-only elsewhere.",
              file=sys.stderr)

    # Load user allowlist
    if args.allowlist:
        al_path = Path(args.allowlist)
        if al_path.exists():
            for line in al_path.read_text().splitlines():
                token = line.strip()
                if token and not token.startswith("#"):
                    _USER_ALLOWLIST.add(token)

    demo_only = args.demo_only
    demo = args.demo or demo_only
    findings = run(demo, demo_only=demo_only)

    # Apply baseline diff
    if args.baseline:
        findings = diff_baseline(findings, Path(args.baseline))

    # Save snapshot
    if args.snapshot:
        snap_path = Path(args.snapshot)
        snap_path.write_text(json.dumps(snapshot(findings), indent=2))
        print(f"snapshot saved: {snap_path}  ({len(findings)} findings)", file=sys.stderr)
        # If --snapshot is the only output flag, also print a summary
        if not (args.json or args.sarif or args.html):
            report(findings, demo_mode=demo)

    # Outputs (can stack --json + --html, etc.)
    if args.sarif:
        print(json.dumps(to_sarif(findings), indent=2))
    elif args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif not args.snapshot:
        report(findings, demo_mode=demo)

    if args.html:
        html_path = Path(args.html)
        to_html(findings, html_path)
        print(f"HTML report: {html_path}", file=sys.stderr)

    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
