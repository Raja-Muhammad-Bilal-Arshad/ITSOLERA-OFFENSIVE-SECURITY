# References & Source Annotations
# CVE-2021-3156 — Baron Samedit

**ITSOLERA Red Team Internship 2026 | Member 3 Deliverable**
**Project:** Offensive Security — Exploit Development for Known CVE
**Document:** docs/references.md

---

## How to Use This Document

Each reference is annotated with:
- What information it contains
- Which sections of the final report it supports
- How to cite it (specific claim → specific source)

---

## Category 1 — Official CVE and NVD Records

### 1.1 MITRE CVE Entry
- **URL:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156
- **Contains:** Official CVE description, assignee (Red Hat), reference list,
  CWE classification (CWE-122: Heap-Based Buffer Overflow).
- **Cite for:** CVE ID, CWE number, official description of the vulnerability.
- **Note:** The MITRE entry is the canonical identifier. Always verify that
  the CVE number in the report matches this entry exactly: `CVE-2021-3156`.

### 1.2 NVD (National Vulnerability Database) Entry
- **URL:** https://nvd.nist.gov/vuln/detail/CVE-2021-3156
- **Contains:** Full CVSS v3.1 vector string
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, score 7.8 HIGH, CPE
  records for affected packages, exploitability/impact sub-scores, and all
  cross-referenced vendor advisories.
- **Cite for:** CVSS score and vector string (cite NVD directly, not secondary
  sources, for accuracy). Also the authoritative list of affected software versions.
- **Note:** The CVSS vector cited in `payloads.TXT` header
  (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — score 7.8) matches the NVD entry.

---

## Category 2 — Primary Discovery and Research

### 2.1 Qualys Research Team Advisory (Primary Discoverer)
- **URL:** https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
- **Contains:** Full root cause explanation from the team that discovered the
  bug. The nickname "Baron Samedit" originates here. Includes: diff-level
  analysis of the vulnerable `set_cmnd()` function, the two-pass size/copy
  mechanism, the off-by-one description, affected version ranges, distribution
  compatibility matrix, and the canary test (`sudoedit -s '\'`).
- **Cite for:**
  - The name "Baron Samedit"
  - The `set_cmnd()` off-by-one root cause description
  - Affected version ranges (1.8.2 – 1.8.31p2, 1.9.0 – 1.9.5p1)
  - The canary test and what its outputs mean
  - Disclosure date (January 26, 2021)
  - CVSS score (7.8 HIGH)
- **Referenced in:** `payloads.TXT` header (line 18), exploit.py docstring (line 49).
- **Priority:** This is the highest-priority technical source. Cite it for
  any claim about the root cause.

---

## Category 3 — Vendor Resources

### 3.1 sudo Official Security Advisories Page
- **URL:** https://www.sudo.ws/security/advisories/
- **Contains:** All official sudo security advisories. The CVE-2021-3156
  entry details what was changed and which versions are covered.
- **Cite for:** Confirming the patched version numbers (1.8.32 and 1.9.5p2).

### 3.2 sudo 1.9.5p2 Release Notes (Patch for 1.9.x branch)
- **URL:** https://www.sudo.ws/releases/stable/#1.9.5p2
- **Contains:** Official release notes confirming the 1.9.5p2 patch for the
  1.9.x branch of sudo. The patch adds pre-check validation in `set_cmnd()`.
- **Cite for:** Confirming the specific code change introduced in the patch.

### 3.3 sudo 1.8.32 Release Notes (Patch for 1.8.x branch)
- **URL:** https://www.sudo.ws/releases/legacy/#1.8.32
- **Contains:** 1.8.32 release notes patching the 1.8.x branch simultaneously
  with 1.9.5p2 on January 26, 2021.
- **Cite for:** The 1.8.x patched version and the dual-branch simultaneous release.

### 3.4 Ubuntu Security Notice USN-4705-1
- **URL:** https://ubuntu.com/security/notices/USN-4705-1
- **Contains:** Ubuntu-specific advisory listing affected package versions for
  Ubuntu 16.04, 18.04, and 20.04, with the fixed package versions. Relevant
  because the lab uses Ubuntu 20.04 and the patch for Ubuntu is
  `1.8.31-1ubuntu1.2` (note: version string still says 1.8.31 — this is why
  the canary test is required to confirm patch status).
- **Cite for:** Ubuntu-specific patched package version; the reason version
  string alone is insufficient on Ubuntu.

### 3.5 Red Hat / CentOS Security Advisory
- **URL:** https://access.redhat.com/security/cve/cve-2021-3156
- **Contains:** Red Hat affected package list, errata (RHSA-2021:0221), and
  fixed package versions for RHEL 6, 7, and 8.
- **Cite for:** RHEL/CentOS specific remediation steps in the mitigation section.

### 3.6 Apple Security Update 2021-001 (macOS)
- **URL:** https://support.apple.com/en-us/HT212147
- **Contains:** Apple's patch for the same bug in macOS Big Sur's bundled sudo
  (1.8.31p1), released February 1, 2021.
- **Cite for:** Confirming the bug's cross-platform nature (macOS also affected).
  Referenced in `payloads.TXT` Section 6.1.

---

## Category 4 — Vulnerability Databases

### 4.1 ExploitDB — Entry EDB-49521
- **URL:** https://www.exploit-db.com/exploits/49521
- **Contains:** Published PoC exploit entry for CVE-2021-3156 on ExploitDB.
  Includes shell-based and Python-based PoC implementations.
- **Cite for:** Confirming public exploitability and the existence of weaponized
  code at the time of the task.
- **Referenced in:** `payloads.TXT` header (line 22): `ExploitDB: https://www.exploit-db.com/exploits/49521`

### 4.2 Rapid7 Vulnerability Database / Technical Analysis
- **URL:** https://www.rapid7.com/blog/post/2021/02/04/the-sudoers-also-singly-2021-sudo-heap-overflow/
- **Contains:** Rapid7's in-depth heap analysis including: how the heap layout
  must be controlled, the three exploitation strategies (per worawit's PoC),
  heap grooming via environment variables, discussion of glibc tcache behavior,
  and the Metasploit module details.
- **Cite for:** Heap grooming explanation, environment variable technique
  (`LC_ALL`, `SUDO_EDITOR`), the three-strategy overview, and Metasploit module
  existence.

### 4.3 Rapid7 Metasploit Module
- **Module:** `exploit/linux/local/sudo_baron_samedit`
- **URL:** https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/sudo_baron_samedit.rb
- **Contains:** Production-quality Metasploit exploit module with auto-detection
  of heap strategy based on glibc version. Confirms reliable exploitation on
  Ubuntu 20.04, 18.04, Debian 10, and Fedora 33.
- **Cite for:** Demonstrating that automated, reliable exploitation tooling
  exists and is publicly available, confirming severity.

---

## Category 5 — Public Proof-of-Concept Code

### 5.1 blasty's PoC (C Implementation — Strategy 1)
- **URL:** https://github.com/blasty/CVE-2021-3156
- **Contains:** The first widely published PoC after Qualys disclosure. Written
  in C. Targets Ubuntu 20.04 via the `service_user` struct approach (Strategy 1
  in public naming, but targets the 20.04 layout as blasty defined it). Uses
  `SUDO_EDITOR` environment variable to inject commands.
- **Cite for:** The `SUDO_EDITOR` injection technique; the `service_user` struct
  target; and the concept of environment variable heap grooming.
- **Referenced in:** `exploit.py` docstring (line 47), `payloads.TXT` header
  (line 20), Summary Cheatsheet Section 12.

### 5.2 worawit's PoC (Python — Three Strategies)
- **URL:** https://github.com/worawit/CVE-2021-3156
- **Contains:** A comprehensive Python PoC with three separate heap exploitation
  strategies tuned to different glibc versions:
  - Strategy 1: glibc 2.27 → Ubuntu 18.04 / Debian 10
  - Strategy 2: glibc 2.31 → Ubuntu 20.04 (**the lab target**)
  - Strategy 3: glibc 2.33+ → Fedora 33+
  More portable than blasty's C version and the primary reference for
  `select_heap_strategy()` and `build_overflow_argument()` in Member 2's code.
- **Cite for:** The three-strategy framework; heap strategy selection by glibc
  version; argument construction principles; the `LC_ALL` grooming technique.
- **Referenced in:** `exploit.py` docstring (line 48), `payloads.TXT` header
  (line 21), `select_heap_strategy()` TODO comment (line 480), Summary
  Cheatsheet Section 12.

### 5.3 Member 2's exploit.py (ITSOLERA Implementation)
- **Location:** `exploit/exploit.py` (this repository)
- **Contains:** Python3 exploit framework implementing:
  - Platform check, version detection, canary test (fully implemented)
  - System info collection (glibc, arch, OS — fully implemented)
  - `select_heap_strategy()` TODO stub with full implementation guide
  - `build_overflow_argument()` TODO stub with full implementation guide
  - `trigger_overflow_and_escalate()` TODO stub with full implementation guide
  - `--check-only`, `--safe-mode`, `--cmd`, `--verbose`, `--output` flags
- **Cite for:** The primary exploit code being demonstrated. All annotations
  in `exploit_walkthrough.md` reference this file directly.

### 5.4 Member 2's payloads.TXT (ITSOLERA Payload Research)
- **Location:** `exploit/payloads.TXT` (this repository)
- **Contains:** 12 sections of original payload research including:
  - Vulnerability trigger analysis and alternative trigger forms
  - Canary payload matrix with full output descriptions
  - The `set_cmnd()` two-pass mechanism with exact worked examples
  - Environment variable heap grooming analysis
  - Three-strategy heap overview
  - Platform compatibility matrix (11 distributions tested)
  - 9 documented failed exploit attempts with analysis
  - Post-exploitation validation payload collection
  - Blue team detection signatures (auditd, Falco, Sigma, journald)
  - Patched vs. vulnerable behavior comparison matrix
  - Related sudo CVE historical context
- **Cite for:** The two-pass `set_cmnd()` analysis; argument length/heap
  chunk size tables; environment variable effects; platform compatibility;
  failed attempt documentation; detection rules.

---

## Category 6 — Lab Environment References

### 6.1 Member 1's SETUP.md
- **Location:** `lab/SETUP.md` (this repository)
- **Contains:** Step-by-step lab setup instructions:
  - `docker-compose up -d --build` to start
  - `docker exec -it cve_2021_3156_lab /bin/bash` to access
  - `docker cp ../exploit/exploit.py cve_2021_3156_lab:/home/tester/` to load exploit
  - `docker-compose down && docker-compose up -d` to reset
- **Cite for:** Lab access and reset procedures in the final report's
  "Lab Setup" section.

### 6.2 Member 1's config_notes.md
- **Location:** `lab/config_notes.md` (this repository)
- **Contains:**
  - sudo version: 1.8.31 at `/usr/local/bin/sudo`
  - Default user: `tester` with password `password`
  - `tester` explicitly not in `/etc/sudoers`
  - No extra dependencies beyond Python3 and build tools
- **Cite for:** Confirming the lab user has zero sudo permissions (proving
  the exploit bypasses sudoers authorization entirely).

### 6.3 Member 1's Dockerfile
- **Location:** `lab/Dockerfile` (this repository)
- **Contains:**
  - `FROM ubuntu:20.04` base image → Ubuntu 20.04 LTS
  - `wget https://www.sudo.ws/dist/sudo-1.8.31.tar.gz` → confirms exact version
  - Compiled from source: `./configure && make && make install`
  - `useradd -m tester && echo "tester:password" | chpasswd`
  - `USER tester` → container starts as unprivileged user
- **Cite for:** Confirming the exact sudo version (1.8.31, not a patched
  Ubuntu package), the OS version (Ubuntu 20.04 → glibc 2.31 → Strategy 2),
  and the unprivileged starting user.

### 6.4 Member 1's docker-compose.yml
- **Location:** `lab/docker-compose.yml` (this repository)
- **Contains:** Container definition with `container_name: cve_2021_3156_lab`,
  `tty: true` and `stdin_open: true` for interactive shell access.
- **Cite for:** Container name used in `docker exec` and `docker cp` commands.

---

## Category 7 — Supporting and General References

### 7.1 GTFOBins — sudo Entry
- **URL:** https://gtfobins.github.io/gtfobins/sudo/
- **Contains:** Legitimate uses of sudo for privilege escalation in CTF and
  penetration testing contexts. Useful background for understanding sudo's
  broader attack surface beyond CVE-2021-3156.
- **Cite for:** Context on sudo as a frequent LPE target in general.

### 7.2 PayloadsAllTheThings — Linux Privilege Escalation
- **URL:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- **Contains:** General Linux LPE techniques. CVE-2021-3156 fits the
  "kernel/setuid binary" category of this reference.
- **Cite for:** Placing CVE-2021-3156 in the broader landscape of Linux
  privilege escalation techniques.

### 7.3 CWE-122 — Heap-Based Buffer Overflow Definition
- **URL:** https://cwe.mitre.org/data/definitions/122.html
- **Contains:** Formal definition and examples of CWE-122 (the CWE class
  for CVE-2021-3156). Includes: description, extended description, examples,
  and observed examples.
- **Cite for:** Formal CWE classification and definition in the vulnerability
  summary section of the report.

### 7.4 glibc malloc Documentation (Heap Internals)
- **URL:** https://sourceware.org/glibc/wiki/MallocInternals
- **Contains:** Official documentation of glibc's malloc implementation,
  including chunk headers, tcache bins, alignment rules, and allocation
  strategies for glibc 2.26+.
- **Cite for:** Technical explanations of heap chunk layout, tcache bin sizing,
  and 16-byte alignment used in the heap grooming section.

---

## Citation Quick-Reference Table

| Claim to Cite                                    | Source                                  | Category |
|--------------------------------------------------|-----------------------------------------|----------|
| CVE ID and CWE classification                    | MITRE (1.1)                             | Official |
| CVSS vector string `AV:L/AC:L/PR:L/...` / 7.8   | NVD (1.2)                               | Official |
| "Baron Samedit" name and disclosure date         | Qualys Advisory (2.1)                   | Primary  |
| `set_cmnd()` off-by-one root cause               | Qualys Advisory (2.1)                   | Primary  |
| Affected versions 1.8.2–1.8.31p2, 1.9.0–1.9.5p1 | Qualys Advisory (2.1) + sudo.ws (3.1)  | Primary  |
| Canary test and output meaning                   | Qualys Advisory (2.1) + payloads.TXT (5.4) | Primary |
| Patched version numbers (1.8.32, 1.9.5p2)       | sudo.ws (3.2, 3.3)                      | Vendor   |
| Ubuntu patched package version                   | USN-4705-1 (3.4)                        | Vendor   |
| ExploitDB public PoC entry                       | EDB-49521 (4.1)                         | ExploitDB|
| Three heap strategies by glibc version           | Rapid7 (4.2) + worawit PoC (5.2)       | Research |
| Environment variable heap grooming               | Rapid7 (4.2) + payloads.TXT (5.4)      | Research |
| SUDO_EDITOR injection technique                  | blasty PoC (5.1) + payloads.TXT (5.4)  | PoC      |
| Platform compatibility matrix                    | payloads.TXT Section 6 (5.4)            | Team     |
| Failed exploit attempts                          | payloads.TXT Section 7 (5.4)            | Team     |
| Detection rules (auditd, Falco, Sigma)           | payloads.TXT Section 9 (5.4)            | Team     |
| Lab sudo version confirmation (1.8.31)           | Dockerfile (6.3) + config_notes.md (6.2)| Lab     |
| Lab user has no sudo perms                       | config_notes.md (6.2)                   | Lab      |
| Lab OS = Ubuntu 20.04 → glibc 2.31               | Dockerfile (6.3)                        | Lab      |
| Lab reset procedure                              | SETUP.md (6.1)                          | Lab      |
| Two-pass `set_cmnd()` mechanism                  | payloads.TXT Section 3 (5.4)            | Team     |
| ASLR does not prevent exploit                    | payloads.TXT Section 7 / Attempt 09 (5.4) | Team  |
| Compile-time mitigations ineffective             | payloads.TXT Section 6.3 (5.4)          | Team     |

---

## URL Status Note

All URLs were verified as of the ITSOLERA internship period (August 2026).
GitHub repositories, vendor advisory pages, and NVD entries may change URL
structure over time. If a link is broken, search the domain root for the
CVE identifier `CVE-2021-3156` or the project name.

Primary sources that should remain stable:
- `nvd.nist.gov/vuln/detail/CVE-2021-3156` (US government — stable)
- `cve.mitre.org` (MITRE — stable)
- `www.sudo.ws` (official sudo project — stable)
- `ubuntu.com/security/notices/USN-4705-1` (Ubuntu — stable)

---

*ITSOLERA Red Team Internship 2026 | Task 3 | Member 3 | CVE-2021-3156 (Baron Samedit)*
