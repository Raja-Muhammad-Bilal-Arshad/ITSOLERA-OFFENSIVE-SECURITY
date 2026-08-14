# CVE-2021-3156 — Baron Samedit
## ITSOLERA Red Team Internship 2026 | Task 3

> **⚠️ FOR EDUCATIONAL / ISOLATED LAB USE ONLY**
> Do not run any exploit code outside the provided Docker lab. All testing must remain in the isolated container described below.

---

## Overview

This repository contains the complete research, lab setup, exploit framework, and documentation for **CVE-2021-3156 (Baron Samedit)** — a heap-based buffer overflow in the `sudo` utility that allows any local unprivileged user to escalate to root without credentials or sudo permissions.

| Field | Value |
|---|---|
| CVE ID | CVE-2021-3156 |
| Nickname | Baron Samedit |
| Vulnerability | Heap-Based Buffer Overflow in `set_cmnd()` |
| Affected Versions | sudo 1.8.2 – 1.8.31p2 and 1.9.0 – 1.9.5p1 |
| Fixed Versions | sudo 1.8.32 / 1.9.5p2 |
| CVSS v3.1 Score | 7.8 HIGH |
| Lab Target | Ubuntu 20.04, sudo 1.8.31 (Docker container) |
| Heap Strategy | Strategy 2 (glibc 2.31) |

---

## Repository Structure

```
Task3/
├── README.md                       ← You are here
│
├── lab/                            ← Member 1: Docker lab environment
│   ├── Dockerfile                  ← Builds Ubuntu 20.04 + sudo 1.8.31 from source
│   ├── docker-compose.yml          ← Service definition for the vulnerable container
│   ├── SETUP.md                    ← Step-by-step lab setup guide
│   └── config_notes.md             ← Lab configuration details and notes
│
├── exploit/                        ← Member 2: Exploit code and payload research
│   ├── exploit.py                  ← Python3 exploit framework (checks + canary + TODO stubs)
│   └── payloads.TXT                ← Payload research, analysis, and failed attempts
│
├── docs/                           ← Member 3: Technical documentation
│   ├── root_cause_analysis.md      ← Deep-dive into set_cmnd() off-by-one and heap mechanics
│   ├── exploit_walkthrough.md      ← Line-by-line annotation of exploit.py and payloads.TXT
│   ├── mitigation.md               ← Patch guidance, detection rules, hardening steps
│   └── references.md               ← Annotated bibliography with citation guidance
│
├── proof/                          ← Member 4: Exploitation evidence (screenshots/logs)
│   └── [Add screenshots here]      ← See Proof Collection section below
│
└── report/
    └── CVE-2021-3156_Report.docx   ← Final consolidated report (all sections)
```

---

## Quick Start — Lab Setup

### Prerequisites
- Docker and Docker Compose installed
- ~500MB disk space for the Ubuntu 20.04 base image

### 1. Build and Start the Vulnerable Container

```bash
cd lab/
docker-compose up -d --build
```

### 2. Access the Container Shell

```bash
docker exec -it cve_2021_3156_lab /bin/bash
# You will be logged in as: tester (UID > 0, NOT in /etc/sudoers)
```

### 3. Verify the Environment

```bash
# Inside the container:
sudo --version          # Should show: Sudo version 1.8.31
id                      # Should show: uid=1001(tester)
sudo -l 2>&1            # Should show: not allowed to run sudo
ldd --version           # Should show: glibc 2.31
```

### 4. Confirm the Vulnerability (Canary Test)

```bash
sudoedit -s '\' 2>&1
# VULNERABLE:  "sudoedit: /\: not a regular file"  ✅
# PATCHED:     "sudoedit: invalid argument"          ❌
```

### 5. Load the Exploit Script

```bash
# From your host machine:
docker cp ../exploit/exploit.py cve_2021_3156_lab:/home/tester/

# Inside the container:
python3 exploit.py --check-only     # Runs all prerequisite checks
python3 exploit.py --safe-mode      # Canary test + pre-exploit state
python3 exploit.py --cmd "id"       # Full LPE attempt (requires TODO impl)
```

### 6. Reset the Environment

```bash
docker-compose down
docker-compose up -d
```

---

## Exploit Framework — exploit.py

### Usage

```
python3 exploit.py [OPTIONS]

Options:
  --check-only    Run prerequisite checks only (no canary, no exploit)
  --safe-mode     Run checks + canary test (no exploitation attempt)
  --cmd CMD       Run CMD as root via LPE (requires TODO implementation)
  --verbose       Show detailed output for all steps
  --output FILE   Save results to FILE
  --help          Show this help message
```

### Three-Phase Architecture

```
Phase 1 — Prerequisite Checks (IMPLEMENTED)
  ✅ check_platform()          → Confirm Linux x86_64
  ✅ check_sudoedit_present()  → Find sudoedit in PATH
  ✅ check_sudo_version()      → Confirm 1.8.31 is in vulnerable range
  ✅ check_current_user()      → Confirm non-root, no sudo perms
  ✅ get_system_info()         → Collect glibc version, arch, OS

Phase 2 — Canary Test (IMPLEMENTED)
  ✅ run_canary_test()         → Run sudoedit -s '\' and parse output
                                 "not a regular file" → VULNERABLE
                                 SIGSEGV/SIGABRT      → VULNERABLE
                                 "invalid argument"   → PATCHED

Phase 3 — LPE Exploitation (TODO STUBS — implement from worawit/blasty PoC)
  ⬜ select_heap_strategy()    → Choose Strategy 2 for glibc 2.31
  ⬜ build_overflow_argument() → Craft padded arg ending with '\'
  ⬜ trigger_overflow_and_escalate() → Set LC_ALL + SUDO_EDITOR, run exploit
```

### Heap Strategy for the Lab

The Docker container runs Ubuntu 20.04 with glibc 2.31. This requires **Strategy 2**.

| System | glibc | Strategy | Target Struct |
|--------|-------|----------|---------------|
| Ubuntu 20.04 (this lab) | 2.31 | **Strategy 2** | sudoers_role/user_info |
| Ubuntu 18.04 | 2.27 | Strategy 1 | service_user |
| Fedora 33+ | 2.33+ | Strategy 3 | utmp adjacent |

Reference implementations:
- Strategy 1 (C): https://github.com/blasty/CVE-2021-3156
- All 3 strategies (Python): https://github.com/worawit/CVE-2021-3156

---

## How the Exploit Works

The vulnerability is in `set_cmnd()` inside `src/sudo.c`. When sudo is invoked with `-s` (shell mode) and an argument ending with a backslash `\`, a two-pass processing loop has an off-by-one error:

```
Pass 1 (size calculation):  counts the '\' as 1 byte → malloc(N)
Pass 2 (data copy):         from++ past '\0' → reads 1 byte OUTSIDE the buffer
                             writes that byte to cmnd_args[N-1]
                             → one-byte heap overflow into adjacent chunk
```

The adjacent heap chunk contains a sudo internal struct. The overflowed byte corrupts a pointer in that struct. When sudo later dereferences the pointer (to find which "editor" to run), it follows the corrupted address, which is steered toward `SUDO_EDITOR` — an attacker-controlled environment variable. Since `sudoedit` is a setuid-root binary (EUID=0 is set by the kernel before any code runs), the attacker's command executes as root.

**Key:** This happens **before** sudo reads `/etc/sudoers`. The `tester` user has no sudoers entry — yet the exploit works.

---

## Proof Collection — Member 4

After running the exploit successfully inside the Docker container, collect the following evidence:

```bash
# Screenshot 1: Pre-exploit state
id && sudo -l 2>&1

# Screenshot 2: Canary test output
sudoedit -s '\' 2>&1

# Screenshot 3: exploit.py --check-only output
python3 exploit.py --check-only

# Screenshot 4: Full LPE — id as root
python3 exploit.py --cmd "id"

# Screenshot 5: Root file access (proves full escalation)
python3 exploit.py --cmd "cat /etc/shadow | head -3"

# Collect all evidence at once:
{
  echo "=== PRE-EXPLOIT ==="; id; sudo -l 2>&1
  echo "=== CANARY ==="; sudoedit -s '\' 2>&1
  echo "=== EXPLOIT ==="; python3 exploit.py --cmd "id && whoami"
} | tee /tmp/exploit_proof.txt
```

Place all screenshots in the `proof/` directory and reference them in the report.

---

## Vulnerability Summary

### Why It's Dangerous

1. **No sudo permissions needed** — exploit fires before `/etc/sudoers` is read
2. **No credentials needed** — any local account with a shell can run it
3. **Bypasses all compile-time mitigations** — ASLR, stack canaries, PIE, RELRO, NX all ineffective against this heap overflow
4. **~10 years undetected** — bug existed since sudo 1.8.2 (~2011)
5. **Public exploit within 24 hours** — weaponized code available immediately after disclosure

### Canary Test Output Matrix

| Output | Exit Code | Verdict |
|--------|-----------|---------|
| `sudoedit: /\: not a regular file` | 1 | ✅ VULNERABLE |
| Segmentation fault | 139 | ✅ VULNERABLE |
| Abort (core dumped) | 134 | ✅ VULNERABLE |
| `sudoedit: invalid argument` | 1 | ❌ PATCHED |
| `usage: sudoedit [...]` | 1 | ❌ PATCHED |

---

## Fix / Patch

```bash
# Ubuntu / Debian:
sudo apt-get update && sudo apt-get install --only-upgrade sudo

# Confirm fix (live canary — more reliable than version string):
sudoedit -s '\' 2>&1
# Must show: "sudoedit: invalid argument"  ← SAFE
```

Patched versions: **sudo 1.8.32** or **sudo 1.9.5p2** (released January 26, 2021).

Note: Ubuntu 20.04 backports the patch as `1.8.31-1ubuntu1.2` — the version string still says 1.8.31, which is why the canary test must be used to confirm patch status.

---

## Detection

### Quick auditd Rule

```bash
auditctl -a always,exit -F arch=b64 -S execve \
         -F exe=/usr/local/bin/sudoedit \
         -k baron_samedit
# View: ausearch -k baron_samedit --start today
```

### Alert On

- `"not a regular file"` in sudo logs from a non-admin user
- `sudoedit` process crashing (SIGSEGV/SIGABRT)
- Non-root process spawning a root-UID child

Full detection rules (auditd, Falco, Sigma, journald) are in `docs/mitigation.md`.

---

## References

| Source | URL | Used For |
|--------|-----|----------|
| Qualys Advisory (discoverers) | https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit | Root cause, affected versions, canary |
| NVD Entry | https://nvd.nist.gov/vuln/detail/CVE-2021-3156 | CVSS score, CPE records |
| MITRE CVE | https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156 | Official CVE record |
| sudo.ws Advisory | https://www.sudo.ws/security/advisories/ | Patched version confirmation |
| Ubuntu USN-4705-1 | https://ubuntu.com/security/notices/USN-4705-1 | Ubuntu-specific patch version |
| ExploitDB EDB-49521 | https://www.exploit-db.com/exploits/49521 | Public PoC reference |
| blasty PoC (C) | https://github.com/blasty/CVE-2021-3156 | Strategy 1 reference |
| worawit PoC (Python) | https://github.com/worawit/CVE-2021-3156 | Strategy 2+3 reference |
| Rapid7 Analysis | https://www.rapid7.com/blog/post/2021/02/04/the-sudoers-also-singly-2021-sudo-heap-overflow/ | Heap grooming detail |
| GTFOBins sudo | https://gtfobins.github.io/gtfobins/sudo/ | General sudo LPE context |

Full annotated bibliography with citation guidance: `docs/references.md`

---

## Ethical Rules

- ✅ Run only inside the isolated Docker lab container
- ✅ No internet-facing interfaces in the lab environment
- ✅ Reset the environment after each test session
- ❌ Do NOT run on any production, shared, or live system
- ❌ Do NOT share exploit output outside the team

---

*ITSOLERA Red Team Internship 2026 | Task 3 | CVE-2021-3156 (Baron Samedit)*
