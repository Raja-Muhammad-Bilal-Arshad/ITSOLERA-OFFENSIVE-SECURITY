# Mitigation & Patch Guidance
# CVE-2021-3156 — Baron Samedit

**ITSOLERA Red Team Internship 2026 | Member 3 Deliverable**
**Project:** Offensive Security — Exploit Development for Known CVE
**Document:** docs/mitigation.md

---

## Executive Summary

CVE-2021-3156 is a heap-based buffer overflow in `sudo`'s `set_cmnd()` function
(versions 1.8.2 – 1.8.31p2 and 1.9.0 – 1.9.5p1). The only complete fix is
upgrading sudo to version **1.8.32** or **1.9.5p2** or later. All compensating
controls below reduce risk but do not eliminate the underlying code vulnerability.

**Priority action: patch immediately.** Public PoC code (blasty, worawit,
Metasploit module `exploit/linux/local/sudo_baron_samedit`) makes this
trivially exploitable by any attacker with local shell access.

---

## 1. Primary Fix — Upgrade sudo

### What changed in the patch

The patch adds a pre-check at the entry of `set_cmnd()` that validates each
argument before the escape processing loop begins. If any argument ends with
a backslash (`\`), the function immediately returns an error with the message
"invalid argument" — before any heap allocation occurs. The off-by-one read
past the null terminator is therefore never triggered.

### Patched version boundaries

| Branch | Last Vulnerable Version | First Patched Version | Released         |
|--------|-------------------------|-----------------------|-----------------|
| 1.8.x  | 1.8.31p2                | **1.8.32**            | January 26, 2021 |
| 1.9.x  | 1.9.5p1                 | **1.9.5p2**           | January 26, 2021 |

### Upgrade by distribution

**Ubuntu / Debian (APT):**
```bash
sudo apt-get update
sudo apt-get install --only-upgrade sudo
sudo --version    # confirm >= 1.8.32 or >= 1.9.5p2
```

For Ubuntu 20.04 specifically, the patched package is
`sudo 1.8.31-1ubuntu1.2` (note: version string still says 1.8.31 but is patched —
this is why the live canary test is required in addition to version checking).

**RHEL / CentOS:**
```bash
sudo yum update sudo
sudo --version
```

**Fedora:**
```bash
sudo dnf update sudo
sudo --version
```

**Arch Linux:**
```bash
sudo pacman -Syu sudo
```

**From source (lab environment — to upgrade the compiled sudo):**
```bash
# Inside the Docker container, as root, or rebuild the Dockerfile:
cd /tmp
wget https://www.sudo.ws/dist/sudo-1.9.5p2.tar.gz
tar xzf sudo-1.9.5p2.tar.gz
cd sudo-1.9.5p2
./configure
make
make install
sudo --version    # should show 1.9.5p2
```

**Update Member 1's Dockerfile to patch the lab:**
Change line in `lab/Dockerfile`:
```dockerfile
# VULNERABLE (current):
RUN wget https://www.sudo.ws/dist/sudo-1.8.31.tar.gz && \
    tar xzf sudo-1.8.31.tar.gz && \
    cd sudo-1.8.31 && \

# PATCHED (demo):
RUN wget https://www.sudo.ws/dist/sudo-1.9.5p2.tar.gz && \
    tar xzf sudo-1.9.5p2.tar.gz && \
    cd sudo-1.9.5p2 && \
```
Then rebuild: `docker-compose down && docker-compose up -d --build`

---

## 2. Post-Patch Verification

After applying any fix, run **both** of the following checks. Version
string alone is not sufficient (Ubuntu backports patches without bumping
the main version number).

### Check 1 — Version string:
```bash
sudo --version | head -1
# Should show 1.8.32, 1.9.5p2, or higher
# Ubuntu 20.04 patched: may still show "1.8.31" — use Check 2
```

### Check 2 — Live canary test (definitive):
```bash
sudoedit -s '\' 2>&1
# PATCHED:     outputs "sudoedit: invalid argument"  ← SAFE
# STILL VULN:  outputs "not a regular file" or crashes ← NOT PATCHED
```

### Check 3 — Run exploit.py check-only mode:
```bash
python3 exploit.py --check-only
# All checks FAIL on a patched system (version check fails, canary fails)
# Expected: "sudo version (vulnerable): FAIL" — confirms patch is active
```

---

## 3. Compensating Controls (If Immediate Patching Is Not Possible)

These are **temporary mitigations only**. They reduce the attack surface
but do not fix the underlying `set_cmnd()` code bug. Schedule the patch as
soon as possible after implementing these.

### 3.1 Remove or Restrict Access to sudoedit

The exploit specifically requires `sudoedit -s`. Removing or restricting the
binary removes the primary attack vector:

```bash
# Option A: Remove the setuid bit from sudoedit
# WARNING: This breaks ALL sudo functionality. Only use if sudo is not needed.
chmod u-s /usr/bin/sudoedit
chmod u-s /usr/local/bin/sudoedit   # for compiled installs (like the lab)

# Verify setuid bit is removed:
ls -la /usr/bin/sudoedit
# Should show: -rwxr-xr-x (no 's' in owner execute position)

# Option B: Restrict execution to specific groups (less disruptive)
chown root:sudo_admins /usr/local/bin/sudoedit
chmod 0110 /usr/local/bin/sudoedit
```

**Important:** Option A makes sudo entirely non-functional. Use only on
systems where sudo is genuinely not needed or as an emergency last resort.

### 3.2 Restrict Local User Accounts

CVE-2021-3156 requires a local interactive account. Reducing the number of
such accounts narrows the attacker pool:

```bash
# Review current interactive accounts:
awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1, $3, $7}' /etc/passwd

# Lock unused accounts:
passwd -l <username>

# Verify locked:
passwd -S <username>    # should show 'L' for locked

# For lab: the 'tester' account is intentionally active for demonstration.
# In production, disable any account that does not require interactive login.
```

### 3.3 Implement sudo's Secure Usage Policies

While the exploit bypasses sudoers entirely, hardening sudoers reduces
post-exploit impact and removes legitimate escalation paths:

```bash
# Edit /etc/sudoers via:
visudo

# Remove ALL=(ALL) NOPASSWD:ALL entries — never grant unrestricted access
# Replace with specific command grants only:
# tester  ALL=(ALL) /usr/bin/systemctl restart nginx  ← specific command only

# Disable sudoedit for all users unless explicitly needed:
Defaults !env_editor
```

### 3.4 Disable Shell Mode if Not Required

If your environment does not need `sudo -s` or `sudo -i` (shell mode),
they can be disabled in sudoers. This removes the specific code path
that activates `set_cmnd()` with MODE_SHELL:

```bash
# Add to /etc/sudoers:
Defaults !shellnoargs   # disable shell mode globally
Defaults !env_reset     # ensure env is not passed through
```

**Note:** This does not fix the code bug — it removes one entry point for it.

---

## 4. Detection — Identifying Exploitation Attempts

### 4.1 auditd Rules (Linux Audit Framework)

Install these rules to log all invocations of `sudoedit` with the `-s` flag:

```bash
# Detect all sudoedit -s invocations (primary attack vector):
auditctl -a always,exit -F arch=b64 \
         -S execve \
         -F exe=/usr/local/bin/sudoedit \
         -k baron_samedit

# Detect sudo -s with suspicious arguments:
auditctl -a always,exit -F arch=b64 \
         -S execve \
         -F exe=/usr/local/bin/sudo \
         -k sudo_shell_mode

# Monitor for new SUID files (post-exploitation persistence):
auditctl -a always,exit -F arch=b64 \
         -S chmod -S fchmod -S fchmodat \
         -F perm=x -F auid>=1000 -F auid!=4294967295 \
         -k suid_creation

# Make rules persistent (add to /etc/audit/rules.d/baron_samedit.rules)
# View audit logs:
ausearch -k baron_samedit --start today
ausearch -k sudo_shell_mode | grep -A5 "sudoedit"
```

**Suspicious log patterns to alert on:**
- `"sudoedit: /\: not a regular file"` for a non-admin user (canary probe)
- `sudo` process crashing (SIGSEGV/SIGABRT) immediately after `sudoedit` invocation
- New root-level processes spawned from non-root parent processes
- Processes with UID=0 that have a non-root parent PID (post-exploitation)

### 4.2 syslog / journald Indicators

```bash
# Watch for sudo crash messages in real time:
journalctl -f | grep -i "sudo\|segfault\|signal 11"

# sudo logs to auth.log (Ubuntu/Debian):
tail -f /var/log/auth.log | grep sudoedit

# Check for post-exploitation markers:
grep "not a regular file" /var/log/auth.log | grep -v root
```

### 4.3 Falco Runtime Security Rule

If Falco is deployed, add this rule to detect Baron Samedit exploitation attempts:

```yaml
- rule: CVE-2021-3156 Baron Samedit Attempt
  desc: Detect sudoedit invoked with -s flag by a non-root user
  condition: >
    spawned_process and
    proc.name = "sudoedit" and
    proc.args contains "-s" and
    user.uid != 0
  output: >
    Possible CVE-2021-3156 exploitation attempt
    (user=%user.name uid=%user.uid
     args=%proc.args parent=%proc.pname container=%container.id)
  priority: CRITICAL
  tags: [cve, privilege-escalation, sudo, baron-samedit]
```

### 4.4 Sigma Rule (SIEM Detection)

```yaml
title: CVE-2021-3156 Baron Samedit Exploitation Attempt
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: >
  Detects potential exploitation of CVE-2021-3156 (Baron Samedit)
  via sudoedit -s or sudo -s with a trailing backslash argument.
references:
  - https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
  - https://nvd.nist.gov/vuln/detail/CVE-2021-3156
author: ITSOLERA Red Team Internship 2026
date: 2026/08/14
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'sudoedit -s'
      - 'sudo -s \\'
      - "sudoedit -s '\'"
  condition: selection
falsepositives:
  - Legitimate sudoedit -s usage (rare; review context carefully)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1068
```

### 4.5 Network Indicators (Remote Attack via SSH)

If an attacker connects via SSH before running the exploit:
- SSH connection from an unusual IP address or time of day
- SSH session that immediately runs `sudoedit` and then disconnects
- SSH session where `whoami` output changes from a user to root mid-session
- Multiple rapid sudoedit invocations (canary probing) from the same user

**Recommendation:** Enable SSH session logging and capture full TTY output
with `script(1)` or `auditd` I/O plugin:
```bash
# Add to /etc/audit/auditd.conf:
log_format = ENRICHED
# Enable I/O logging per-session:
auditctl -a exit,always -F arch=b64 -S execve -k exec_monitor
```

---

## 5. Long-Term Hardening Recommendations

### 5.1 Subscribe to sudo Security Advisories

Subscribe to the sudo security mailing list:
`https://www.sudo.ws/mail.html`

Or enable automatic security updates on APT-based systems:
```bash
apt-get install unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
# Edit /etc/apt/apt.conf.d/50unattended-upgrades to enable security updates
```

### 5.2 Apply Principle of Least Privilege to sudoers

Review `/etc/sudoers` and replace broad grants with specific ones:
```bash
# DANGEROUS — do not use:
tester  ALL=(ALL) NOPASSWD:ALL

# BETTER — grant only what is needed:
tester  ALL=(ALL) /usr/bin/systemctl restart nginx
tester  ALL=(ALL) /usr/bin/journalctl -u nginx

# Verify sudoers with:
visudo -c
```

### 5.3 Enable sudo's I/O Logging

Capture a full record of every sudo session for audit purposes:
```bash
# Add to /etc/sudoers:
Defaults log_output
Defaults iolog_dir=/var/log/sudo-io
Defaults iolog_file=%{user}/%{ts}

# View a session log:
sudoreplay /var/log/sudo-io/<user>/<session>
```

Store logs off-system (e.g., to a SIEM or remote syslog) so they cannot be
tampered with after a compromise.

### 5.4 Reduce the Local Attack Surface

CVE-2021-3156 is a **local** privilege escalation — it requires shell access
to the target machine. Reducing local access reduces exploitability:

```bash
# SSH key-only authentication (disable password auth):
# In /etc/ssh/sshd_config:
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no

# Rate-limit SSH connections (fail2ban):
apt-get install fail2ban
systemctl enable fail2ban

# Remove unnecessary local user accounts:
userdel -r <unused_user>

# Check for accounts with UID < 1000 that should not have shell access:
awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {print}' /etc/passwd
```

### 5.5 Implement EDR/Endpoint Monitoring

Configure EDR software to alert on:
- Non-root processes spawning root processes (UID transition 1000 → 0)
- `sudoedit` invocations from accounts not in sudoers
- Heap crash signals (SIGSEGV, SIGABRT) from the sudo binary
- Creation of SUID binaries by non-root users (post-exploitation persistence)

---

## 6. Lab Restoration After Demo

After demonstrating the exploit, restore the Docker lab to a clean state
before the next run:

```bash
# Full environment reset (from the lab/ directory):
docker-compose down
docker-compose up -d --build

# Verify clean state:
docker exec -it cve_2021_3156_lab id
# Should show: uid=1001(tester) gid=1001(tester) groups=1001(tester)

docker exec -it cve_2021_3156_lab sudo --version
# Should show: Sudo version 1.8.31
```

Per `lab/SETUP.md`: *"Reset the environment completely by running
`docker-compose down` followed by `docker-compose up -d`."*

---

## 7. Mitigation Effectiveness Summary

| Control                                  | Eliminates Root Cause? | Reduces Risk? | Notes                                                 |
|------------------------------------------|------------------------|---------------|-------------------------------------------------------|
| Upgrade to 1.8.32 / 1.9.5p2             | ✅ YES                 | ✅ Full       | Only complete fix. Do this first.                     |
| Remove `sudoedit` setuid bit             | ❌ No                  | ✅ Partial    | Removes entry point. Breaks all sudo functionality.   |
| Restrict local user accounts             | ❌ No                  | ✅ Partial    | Reduces attacker pool, not the code bug.              |
| Disable sudo shell mode (sudoers)        | ❌ No                  | ✅ Partial    | Removes `-s` entry point. Doesn't fix `set_cmnd()`.  |
| auditd / Falco / Sigma detection         | ❌ No                  | Detection     | Catches attempts post-hoc. Does not prevent.          |
| Least-privilege sudoers                  | ❌ No                  | ❌ No effect  | Exploit bypasses sudoers entirely — irrelevant.       |
| Stack canaries / ASLR / RELRO / PIE      | ❌ No                  | ❌ No effect  | These mitigations don't protect against heap overflow. |
| SSH key-only + fail2ban                  | ❌ No                  | ✅ Partial    | Reduces likelihood attacker reaches the local shell.  |
| sudo I/O logging                         | ❌ No                  | Detection     | Forensic trail. Does not prevent the exploit.         |

**Bottom line: Patch first. Every other control is a workaround, not a fix.**

---

*References: sudo.ws release notes, Ubuntu USN-4705-1, Qualys Advisory, Rapid7 analysis.*
*Full reference list in `references.md`. Root cause details in `root_cause_analysis.md`.*
