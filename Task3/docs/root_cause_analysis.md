# Root Cause Analysis
# CVE-2021-3156 — Baron Samedit
# Heap-Based Buffer Overflow in sudo → Local Privilege Escalation

**ITSOLERA Red Team Internship 2026 | Member 3 Deliverable**
**Project:** Offensive Security — Exploit Development for Known CVE
**Document:** docs/root_cause_analysis.md

---

## Document Purpose

This document provides the complete technical root cause analysis for
CVE-2021-3156 (Baron Samedit). It covers:

- What the vulnerability is and where it lives in the code
- The precise C-level mechanism of the off-by-one heap overflow
- How it translates into privilege escalation with zero sudo permissions
- Vulnerable vs. patched behavior comparison
- CVSS scoring and severity justification
- Heap grooming and exploitation mechanics (tied to Member 2's lab)
- Platform compatibility matrix
- Why modern mitigations (ASLR, stack canaries, RELRO) do not prevent exploitation
- Timeline and context

---

## 1. CVE Summary

| Field                  | Value                                                            |
|------------------------|------------------------------------------------------------------|
| CVE ID                 | CVE-2021-3156                                                    |
| Nickname               | Baron Samedit                                                    |
| Component              | sudo (Super User DO) — `set_cmnd()` in `src/sudo.c`             |
| Vulnerability Class    | Heap-Based Buffer Overflow (CWE-122)                             |
| Attack Type            | Local Privilege Escalation (LPE)                                 |
| Affected Versions      | sudo 1.8.2 – 1.8.31p2 and sudo 1.9.0 – 1.9.5p1                 |
| Patched Versions       | sudo 1.8.32, sudo 1.9.5p2                                        |
| **Lab Target Version** | **sudo 1.8.31** (compiled from source in Docker — see Dockerfile)|
| Discoverer             | Qualys Research Team                                             |
| Disclosed              | January 26, 2021                                                 |
| CVSS v3.1 Score        | **7.8 HIGH** — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`           |
| Active Exploitation    | Yes — public PoCs within 24 hours of disclosure                  |
| Bug Age                | ~10 years (introduced circa 2011 in sudo 1.8.2)                  |

### Lab Environment Context (from Member 1)

The Docker container used for this project runs:
- **OS:** Ubuntu 20.04 LTS (`ubuntu:20.04` base image)
- **glibc version:** 2.31 (the default for Ubuntu 20.04)
- **sudo:** version 1.8.31, compiled from source (`sudo-1.8.31.tar.gz` from `sudo.ws`)
- **sudo install path:** `/usr/local/bin/sudo` (compiled, not the APT package)
- **Test user:** `tester` (UID > 0, not in `/etc/sudoers`)
- **Architecture:** x86_64

This configuration is **confirmed vulnerable** to CVE-2021-3156 and requires
heap exploitation **Strategy 2** (glibc 2.31 / Ubuntu 20.04 — see Section 6).

---

## 2. Background — What Is sudo and Why Does This Matter

### What sudo does

`sudo` (Super User DO) allows configured users to execute commands as another
user (typically root). It enforces authorization through `/etc/sudoers`.
`sudoedit` is a special form of sudo designed to safely edit files as root.

### Why this vulnerability is uniquely dangerous

> **The heap overflow in `set_cmnd()` occurs entirely before sudo reads
> `/etc/sudoers`.** The authorization model of sudo is never consulted.
> Any local user — regardless of whether they appear in sudoers at all —
> can escalate to root on a vulnerable system.

In the ITSOLERA lab, the `tester` user is explicitly **not** in the sudoers
file (`config_notes.md`: *"The tester user is not in the sudoers file. This
matches the real world conditions for this privilege escalation vulnerability."*)
This is the ideal demonstration of the exploit's most dangerous property.

### Why `sudoedit` specifically

`sudoedit` runs as a **setuid-root binary**. When the kernel executes a
setuid binary, it immediately sets the process's effective UID (EUID) to the
file owner's UID (root = 0), before any user-space code runs. When the heap
overflow redirects execution inside this process, the redirected code inherits
EUID=0 — producing root-level execution without any separate privilege
elevation step.

---

## 3. The Vulnerability — Code-Level Root Cause

### 3.1 The Vulnerable Function: `set_cmnd()`

The bug lives in the function `set_cmnd()` inside sudo's source file
`src/sudo.c`. This function is responsible for building the internal command
argument string (`cmnd_args`) when sudo is invoked in shell mode (the `-s` or
`-i` flags activate `MODE_SHELL` or `MODE_LOGIN_SHELL`).

Shell mode changes how sudo processes arguments: instead of treating them
literally, it applies escape processing to handle special characters. This
escape processing logic contains the off-by-one error.

### 3.2 The Two-Pass Design of `set_cmnd()`

`set_cmnd()` processes command-line arguments in two sequential passes:

**PASS 1 — Size Calculation:**

The function first iterates over every argument to count how many bytes
the internal `cmnd_args` buffer will need, then allocates exactly that
many bytes with `malloc()`.

```c
/* Pseudocode of PASS 1 — size calculation */
cmnd_size = 0;
for each arg in argv[1:] {
    for each char in arg {
        if (char == '\\' AND next_char != '\0') {
            from++;        // skip the escaped char
        }
        cmnd_size++;       // count this char
    }
    cmnd_size++;           // count the space separator
}
cmnd_args = malloc(cmnd_size + 1);   // +1 for null terminator
```

**PASS 2 — Data Copy:**

The function then iterates again, this time copying the processed characters
into the allocated `cmnd_args` buffer.

```c
/* Pseudocode of PASS 2 — data copy */
out = cmnd_args;
for each arg in argv[1:] {
    for each char in arg {
        if (char == '\\' AND next_char != '\0') {
            from++;            // skip backslash
            *out++ = *from;    // copy the char after backslash
        } else {
            *out++ = char;     // copy char as-is
        }
    }
    *out++ = ' ';              // space separator
}
*out = '\0';                   // null terminate
```

### 3.3 The Off-By-One: What Happens When an Argument Ends With `\`

The critical case: when an argument's **last character is a backslash** (`\`),
meaning the character after the backslash is the null terminator (`\0`).

**In PASS 1:**

```
char = '\'    next_char = '\0'
Condition: (char == '\\' AND next_char != '\0')  →  FALSE (next is '\0')
Action:    cmnd_size++    ← backslash is counted as one byte
```

The backslash is counted in the size. So far correct.

**In PASS 2:**

```
char = '\'    next_char = '\0'
Condition: (char == '\\' AND next_char != '\0')  →  FALSE (next is '\0')
Action:    from++           ← pointer advances PAST the null terminator
           *out++ = *from   ← reads and writes the BYTE AFTER '\0'
```

**This is the bug.** In Pass 2, `from++` moves the read pointer one byte
past the end of the argument string's null terminator. The byte at that
location is not part of the argument — it is whatever happens to be in
adjacent heap memory. That uncontrolled garbage byte is then written into
the `cmnd_args` buffer.

**Result:** Pass 2 writes exactly **one more byte** than Pass 1 counted.
The `malloc()` sized the buffer for Pass 1's count. Pass 2 overflows that
buffer by one byte.

### 3.4 The Off-By-One in Exact Terms (Worked Example)

For the argument string `AAAA\` (four A's followed by a backslash):

```
Memory layout: [ A | A | A | A | \ | \0 | ??? ]
Indices:          0   1   2   3   4    5    6
```

**Pass 1 counts:**

| Character | Condition                  | Action     | cmnd_size |
|-----------|----------------------------|------------|-----------|
| `A`       | not backslash              | +1         | 1         |
| `A`       | not backslash              | +1         | 2         |
| `A`       | not backslash              | +1         | 3         |
| `A`       | not backslash              | +1         | 4         |
| `\`       | `\ AND next('\0')` → FALSE | +1         | 5         |
| (space)   | separator                  | +1         | 6         |

`malloc(6 + 1)` = 7 bytes allocated for `cmnd_args`.

**Pass 2 writes:**

| Step | Action                              | Buffer index | Written value         |
|------|-------------------------------------|--------------|-----------------------|
| 1    | `*out++ = 'A'`                      | `out[0]`     | `A`                   |
| 2    | `*out++ = 'A'`                      | `out[1]`     | `A`                   |
| 3    | `*out++ = 'A'`                      | `out[2]`     | `A`                   |
| 4    | `*out++ = 'A'`                      | `out[3]`     | `A`                   |
| 5    | `from++; *out++ = *from`            | `out[4]`     | **byte from `arg[5]` (beyond `\0`)** ← OVERFLOW |
| 6    | `*out++ = ' '`                      | `out[5]`     | ` ` (space)           |
| 7    | `*out = '\0'`                       | `out[6]`     | `\0`                  |

The value written at `out[4]` comes from **one byte past the null terminator**
of the argument string — heap memory that does not belong to the argument.
This is the overflow byte. Its value is whatever the heap allocator placed
there — but through heap grooming (see Section 6), an attacker can control it.

### 3.5 Why the Overflow Is Exploitable (Not Just a Crash)

A single byte overflow might seem trivial, but it is sufficient for reliable
exploitation because:

1. **The overflow lands on the next heap chunk.** glibc's `malloc` places
   allocations sequentially. The byte immediately after `cmnd_args` belongs
   to the chunk header or data of the next heap allocation.

2. **sudo's heap layout is deterministic.** Even with ASLR randomizing the
   heap's base address, the *order* of allocations within sudo's startup is
   always the same. An attacker who understands this order knows exactly
   which struct lands after `cmnd_args`.

3. **The target struct contains actionable pointers.** If the adjacent chunk
   holds a sudo internal struct with a function pointer or a string pointer
   that sudo later dereferences, overwriting even the low byte of that pointer
   can redirect execution to a controlled location.

4. **Environment variables control heap layout.** By setting `LC_ALL`,
   `SUDO_EDITOR`, and other env vars to specific lengths before launching
   `sudoedit`, an attacker pre-populates the heap with allocations that
   push the target struct to exactly the right position adjacent to
   `cmnd_args`. This is called heap grooming (see Section 6).

5. **ASLR is not an obstacle.** The exploit does not require knowing absolute
   addresses — it corrupts relative heap structures within sudo's own address
   space. The heap layout within sudo is deterministic (same allocation order
   every run) even though the heap base address is randomized by ASLR.

---

## 4. The Complete Attack Chain

```
Step 1:  Attacker (UID > 0, not in sudoers) sets environment variables:
            LC_ALL=<groomed length>    → controls heap chunk placement
            SUDO_EDITOR='/bin/sh -c "id"'  → command to execute as root

Step 2:  Attacker runs:  sudoedit -s '<crafted_arg_ending_with_\>'
            ↓
         Kernel executes sudoedit (setuid binary) → sets EUID=0

Step 3:  sudo calls set_cmnd() with MODE_SHELL active
            ↓
         PASS 1: sizes cmnd_args buffer correctly for arg length
            ↓
         malloc(N) allocates cmnd_args on the heap

Step 4:  PASS 2: escape processing loop reaches trailing '\'
            ↓
         from++ → reads past null terminator of argument
            ↓
         *out++ = *from → writes heap garbage byte to cmnd_args[N-1]
            ↓
         cmnd_args buffer OVERFLOWS by one byte into adjacent chunk

Step 5:  The overflow byte lands on adjacent heap struct
         (e.g., service_user, user_info, depending on strategy)
            ↓
         A pointer or size field in that struct is corrupted

Step 6:  sudo continues execution, eventually dereferences the
         corrupted pointer (e.g., to find which editor to run)
            ↓
         Execution follows the corrupted pointer to attacker-controlled memory

Step 7:  sudo exec()s SUDO_EDITOR — the attacker's command
            ↓
         The SUDO_EDITOR process runs with EUID=0 (still root)

Step 8:  uid=0(root) gid=0(root) groups=0(root)
         Privilege escalation complete — without any sudoers entry
```

---

## 5. The Vulnerability Trigger and Canary Test

### 5.1 Minimal Trigger

The simplest command that reaches the vulnerable code path:

```bash
sudoedit -s '\'
```

Components:
- `sudoedit` — the setuid-root binary, required for privilege escalation
- `-s` — enables shell mode (MODE_SHELL), activating the `set_cmnd()` escape
  processing that contains the off-by-one
- `'\'` — single backslash — the off-by-one trigger character

Without `-s`: MODE_SHELL is not activated; `set_cmnd()` is called with
different flags and the escape processing loop is **not entered** — the
backslash passes through without triggering the overflow. *(Confirmed by
failed attempt 01 in Member 2's `payloads.TXT`.)*

Without trailing `\`: the condition `(char == '\\' AND next_char == '\0')` is
never met — no overflow occurs. *(Confirmed by failed attempt 02.)*

### 5.2 Canary Test — Full Output Matrix

Running `sudoedit -s '\' 2>&1` on the lab container produces one of the
following outcomes, each indicating a specific system state:

| Output Observed                              | Exit Code | Verdict                          |
|----------------------------------------------|-----------|----------------------------------|
| `sudoedit: /\: not a regular file`           | 1         | ✅ **VULNERABLE** — arg processed through vulnerable path |
| `sudoedit: /\: not a regular file (ENOENT)`  | 1         | ✅ **VULNERABLE** — same path, ENOENT variant |
| `Segmentation fault (core dumped)`           | 139       | ✅ **VULNERABLE** — overflow reached bad memory (SIGSEGV) |
| `Segmentation fault`                         | 139       | ✅ **VULNERABLE** — SIGSEGV without core dump |
| `Aborted (core dumped)`                      | 134       | ✅ **VULNERABLE** — overflow triggered heap abort (SIGABRT) |
| `sudoedit: invalid argument`                 | 1         | ❌ **PATCHED** — 1.9.5p2+ pre-check active |
| `usage: sudoedit [-AknS] ...`               | 1         | ❌ **PATCHED** — old-style pre-check |
| `sudo: invalid option -- 's'`               | 1         | ❌ **TOO OLD** — version predates 1.7 |

**Why "not a regular file" means vulnerable:**
The vulnerable code path processes the `\` argument all the way through
`set_cmnd()` and into sudo's file existence check — the argument string is
treated as a file path to edit. Since `\` is not a real file, sudo prints
this error. This message proves the vulnerable code path was exercised fully.

**Why "invalid argument" means patched:**
The patch (sudo 1.9.5p2 / 1.8.32) adds an early validation step at the entry
of `set_cmnd()` that explicitly checks for a trailing backslash and rejects
the argument before the escape processing loop ever runs. The vulnerable
code path is never reached on a patched system.

**Why SIGSEGV/SIGABRT means vulnerable:**
On some glibc configurations, even the minimal single-`\` input causes the
off-by-one to write into heap metadata that glibc's allocator then validates
on the next allocation, triggering an abort. This definitively proves heap
corruption is occurring.

*(Exit code reference: 139 = SIGSEGV = signal 11; 134 = SIGABRT = signal 6)*

---

## 6. Heap Grooming and Exploitation Strategies

Converting the one-byte overflow into reliable privilege escalation requires
controlling the heap layout so that the overflow byte lands on a useful field
in the right struct. This is achieved through heap grooming via environment
variables and argument length selection.

### 6.1 glibc Heap Fundamentals (Ubuntu 20.04 / glibc 2.31)

glibc's `malloc` on x86_64 works as follows:
- All allocations are **16-byte aligned** (on x64)
- Each chunk has a **16-byte header** (`prev_size` + `size` fields)
- A `malloc(N)` produces a chunk of actual size: `((N + 15) & ~15) + 16`
- glibc 2.26+ uses a **tcache** (thread-local cache) for small allocations,
  organized in bins by chunk size:

| tcache Bin | Chunk Size Range |
|------------|-----------------|
| 0          | 0x10 – 0x20     |
| 1          | 0x20 – 0x30     |
| 2          | 0x30 – 0x40     |
| 3          | 0x40 – 0x50     ← typical cmnd_args target |
| 4          | 0x50 – 0x60     |
| ...        | ...             |

### 6.2 Argument Length and Heap Placement

The size of the `cmnd_args` allocation is determined by the argument length.
Changing the argument length moves `cmnd_args` into a different tcache bin,
which changes which struct ends up adjacent:

| Argument Length | cmnd_args Size | Heap Chunk Size | tcache Bin |
|-----------------|---------------|-----------------|-----------|
| 1               | 3 bytes        | 0x20            | bin 0     |
| 16              | 18 bytes       | 0x20            | bin 0     |
| 24              | 26 bytes       | 0x30            | bin 1     |
| 32              | 34 bytes       | 0x30            | bin 1     |
| 56              | 58 bytes       | 0x50            | bin 3     |
| 88              | 90 bytes       | 0x70            | bin 5     |

The exploit argument must be sized so `cmnd_args` lands in the same tcache
bin as the target struct, ensuring they are allocated adjacently.

### 6.3 Environment Variables for Heap Grooming

sudo processes several environment variables before `set_cmnd()` runs.
Each env var causes heap allocations of sizes determined by the string length.
By setting these to specific lengths, the attacker pre-positions allocations
so the target struct lands immediately after `cmnd_args`:

| Variable    | sudo's Use                         | Heap Effect                         |
|-------------|-------------------------------------|-------------------------------------|
| `LC_ALL`    | Locale setting for message output  | Allocates locale data of controlled size |
| `LC_MESSAGES` | Locale for messages              | Similar to LC_ALL                   |
| `LANG`      | Fallback locale                    | Smaller locale allocation            |
| `SUDO_EDITOR` | Editor to invoke for sudoedit   | Allocates editor path string        |
| `VISUAL`    | Fallback editor                    | Allocates editor path string        |
| `HOME`      | Home directory path                | Allocates path string in struct     |
| `TZ`        | Timezone                           | Allocates timezone string           |

**Primary grooming variable:** `LC_ALL`
Setting `LC_ALL` to a string of a specific length causes sudo to allocate
a block of memory for locale processing data. By tuning this length, the
attacker slides the heap positions of all subsequent allocations to achieve
the desired layout.

The approximate heap layout within sudo on glibc 2.31 (Ubuntu 20.04):
```
[Heap base]
├── Initial sudo bookkeeping allocations
├── LC_ALL / locale alloc      ← SIZE CONTROLLED by attacker via env var
├── Username / pw_name alloc   ← from getpwuid()
├── SUDO_EDITOR path alloc     ← from environment
├── cmnd_args alloc            ← THE OVERFLOW BUFFER
├── [Adjacent target struct]   ← overwritten by off-by-one byte
└── ...
```

**SUDO_EDITOR:** After exploitation, sudo invokes the "editor" path which has
been corrupted to point at attacker-controlled data. Setting `SUDO_EDITOR`
to an attacker command causes that command to execute as root:
```bash
SUDO_EDITOR='/bin/sh -c "id > /tmp/pwned"'
SUDO_EDITOR='/bin/bash -c "chmod +s /bin/bash"'
```

### 6.4 Three Heap Exploitation Strategies

Public PoC research (Qualys, worawit) identified three distinct strategies
depending on the system's glibc version:

| Strategy | Target Struct       | glibc Version | Lab Target  | Distro                      |
|----------|---------------------|---------------|-------------|------------------------------|
| 1        | `service_user`      | 2.27          | No          | Ubuntu 18.04, Debian 10      |
| **2**    | `sudoers_role/user` | **2.31**      | **YES**     | **Ubuntu 20.04 (our lab)**   |
| 3        | `utmp` adjacent     | 2.33+         | No          | Fedora 33+                   |

**Strategy 1 — Ubuntu 18.04 / glibc 2.27 (blasty's approach):**
Targets the `service_user` struct in sudo's NSS lookup mechanism. The locale
allocation is sized to occupy the chunk immediately before `cmnd_args`. The
overflow byte overwrites the first byte of `service_user.name` (a pointer
field), causing sudo to follow an attacker-controlled address when looking up
the NSS service. Target chunk size: `0x30` (48 bytes).

**Strategy 2 — Ubuntu 20.04 / glibc 2.31 (our lab target):**
glibc 2.31 uses a tcache-first allocation model. The argument is crafted
to produce a `cmnd_args` allocation in the `0x40` tcache bin. Environment
variables pre-populate specific tcache bins so the target struct lands
adjacent. The off-by-one overwrites the LSB of the next chunk's size field
or a pointer in the struct's first member. This is the strategy applicable
to the ITSOLERA Docker lab (Ubuntu 20.04, glibc 2.31).

**Strategy 3 — Fedora 33 / glibc 2.33+:**
Targets the chunk adjacent to sudo's `utmp` write buffer. On newer glibc,
the heap allocator uses a different layout. The off-by-one corrupts the
logging buffer pointer, redirecting a logging write to overwrite a function
pointer. The most glibc-version-sensitive of the three strategies.

**Strategy selection script (run inside lab container):**
```bash
GLIBC=$(ldd --version 2>&1 | head -1 | grep -oP '\d+\.\d+$')
echo "glibc version: $GLIBC"
case "$GLIBC" in
    "2.27") echo "Use Strategy 1 (Ubuntu 18.04 / Debian 10)" ;;
    "2.31") echo "Use Strategy 2 (Ubuntu 20.04)" ;;
    "2.33"|"2.34"|"2.35") echo "Use Strategy 3 (Fedora 33+)" ;;
    *)      echo "Unknown — review worawit PoC for your version" ;;
esac
```

---

## 7. Platform Compatibility Matrix

The following matrix documents vulnerability status across major distributions,
based on Member 2's payload research and public disclosure data:

| Distribution         | sudo Version   | glibc  | Vulnerable? | Strategy |
|----------------------|---------------|--------|-------------|----------|
| **Ubuntu 20.04 LTS** | **1.8.31**    | **2.31** | ✅ **YES** | **2** ← lab |
| Ubuntu 18.04 LTS     | 1.8.21p2      | 2.27   | ✅ YES      | 1        |
| Ubuntu 16.04 LTS     | 1.8.16        | 2.23   | ✅ YES      | 1 (adapt)|
| Debian 10 (Buster)   | 1.8.27        | 2.28   | ✅ YES      | 1        |
| Debian 9 (Stretch)   | 1.8.19p1      | 2.24   | ✅ YES      | 1 (adapt)|
| CentOS 8             | 1.8.29        | 2.28   | ✅ YES      | varies   |
| RHEL 7               | 1.8.23        | 2.17   | ✅ YES      | varies   |
| Fedora 33            | 1.9.3p1       | 2.32   | ✅ YES      | 3        |
| openSUSE Leap 15.2   | 1.9.4p2       | 2.26   | ✅ YES      | varies   |
| macOS Big Sur        | 1.8.31p1      | N/A    | ✅ YES*     | different|
| Ubuntu 20.04 patched | 1.8.31-ubuntu1.2 | 2.31 | ❌ NO    | N/A      |
| Ubuntu 22.04         | 1.9.9         | 2.35   | ❌ NO      | N/A      |

*macOS uses a different allocator; Apple released Security Update 2021-001 on 2021-02-01.

---

## 8. Why Modern Security Mitigations Do Not Prevent Exploitation

A key aspect of CVE-2021-3156 is that it bypasses nearly all modern Linux
binary hardening mechanisms. This is documented to explain why the Ubuntu 20.04
Docker lab (which uses a modern, hardened Ubuntu build) remains exploitable.

| Mitigation                | Status in Ubuntu 20.04 sudo | Effect on This Exploit              |
|---------------------------|------------------------------|-------------------------------------|
| ASLR (system-wide)        | Enabled                      | ❌ No effect — see note below       |
| PIE (position-independent) | Yes — compiled into sudo   | ❌ No effect — no absolute addresses used |
| Stack canaries (SSP)      | Yes — `--with-ssp`          | ❌ No effect — overflow is on heap  |
| Full RELRO (read-only GOT)| Yes                          | ❌ Minimal effect — heap structs used |
| NX/DEP (non-executable stack) | Yes                     | ❌ No effect — no shellcode injected |
| FORTIFY_SOURCE=2          | Yes                          | ⚠️ Partial — may cause abort instead of clean exploit on some configs |

**Why ASLR does not prevent exploitation:**
ASLR randomizes the heap's **base address** between runs. However, the
**order of allocations within sudo** is deterministic — the same structs
are always allocated in the same order relative to each other. The exploit
corrupts relative heap structures, not absolute addresses. No memory leak
or ASLR bypass is required.

**Why stack canaries don't help:**
The vulnerability is a **heap** buffer overflow. Stack canaries protect the
saved return address on the stack; they have no visibility into heap chunk
boundaries. The overflow of `cmnd_args` into the adjacent heap chunk is
completely invisible to stack canary mechanisms.

**Why PIE and RELRO don't help:**
The exploit does not overwrite the GOT (global offset table) or return
addresses. It overwrites **heap data structures** (sudo internal structs)
and redirects execution via pointer corruption within those structs. PIE
and RELRO specifically protect the code/data sections and GOT — not heap
object fields.

**Why no shellcode is needed:**
The exploit redirects sudo to execute `SUDO_EDITOR` — a legitimate sudo
feature for selecting an editor binary. The attacker just sets this env var
to their command. There is no injected shellcode to be blocked by NX/DEP.

---

## 9. Vulnerable vs. Patched Behavior — Complete Comparison

### 9.1 Code-Level Change in the Patch

The patch (sudo 1.8.32 / 1.9.5p2) adds a pre-check at the entry of
`set_cmnd()` that explicitly validates the argument before the escape
processing loop begins:

```c
/* Pseudocode of the patch */
if (arg[strlen(arg) - 1] == '\\') {
    sudo_warnx("invalid argument");
    debug_return_int(-1);
}
```

This check runs before Pass 1, before any heap allocation, and before
the off-by-one can occur. The vulnerable code path is never reached on
a patched system.

### 9.2 Behavioral Comparison Matrix

All payloads below were tested by Member 2 (`payloads.TXT`, Section 10):

| Command                               | Vulnerable 1.8.31           | Patched 1.9.9               |
|---------------------------------------|-----------------------------|-----------------------------|
| `sudoedit -s '\'`                     | "not a regular file" / segfault | "invalid argument"      |
| `sudoedit -s 'A\'`                    | "not a regular file" / crash | "invalid argument"         |
| `sudoedit -s 'AAAA\'`                 | "not a regular file"        | "invalid argument"          |
| `sudoedit -s 'A' 'B\'`               | "not a regular file"        | "invalid argument"          |
| `sudoedit -s 'normal_arg'`           | "not a regular file" (no crash) | "not a regular file"    |
| `sudo -s '\'`                         | "not allowed" (crash possible) | "invalid argument"       |
| `sudo -s 'normal_arg'`               | "not allowed to execute"    | "not allowed to execute"    |
| `sudoedit -s '\' '\' '\'`            | Crash / ambiguous           | "invalid argument"          |
| Exploit with Strategy 2              | uid=0(root) — SUCCESS       | exploit.py check fails      |
| `sudoedit --version`                 | `Sudo version 1.8.31`       | `Sudo version 1.9.9`        |

---

## 10. Negative Results — What Does NOT Work (from Member 2's Research)

These failed attempts from `payloads.TXT` (Section 7) are important for
understanding the exact scope of the vulnerability:

| Attempt | Command | Result | Why It Fails |
|---------|---------|--------|--------------|
| 01 | `sudoedit '\'` (no `-s`) | No overflow | `-s` is required to activate MODE_SHELL and the escape processing loop |
| 02 | `sudoedit -s 'AAAA'` | No overflow | Without trailing `\`, the condition `next_char == '\0'` is never true |
| 03 | `sudoedit -s '\' '\' '\'` | Ambiguous crash | Multiple overflow opportunities but no heap grooming → unpredictable |
| 04 | `sudoedit -s 'A\ B'` | Info only | Mid-string `\` processed correctly (next char is not `\0`); overflow only at end-of-string |
| 05 | Canary on patched sudo 1.9.9 | "invalid argument" | Patch pre-check correctly rejects trailing `\` before processing |
| 06 | Single `\` canary | Confirms vulnerable, not exploitable | Too short for reliable exploitation; overflow lands at unpredictable offset |
| 07 | `sudo -s '\'` | Partial — less reliable | `sudo` (not `sudoedit`) hits a different post-overflow code path; less reliable than `sudoedit -s` |
| 08 | Wrong glibc strategy | Segfault, no LPE | Strategy must exactly match glibc version; wrong strategy corrupts malloc metadata |
| 09 | ASLR bypass attempt | N/A | Not required; exploit does not use absolute addresses |

---

## 11. CVSS v3.1 Score — Full Breakdown

**Vector String:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**Score: 7.8 HIGH**

| CVSS Metric              | Value        | Justification                                              |
|--------------------------|--------------|------------------------------------------------------------|
| Attack Vector (AV)       | Local (L)    | Attacker must have a local account on the system. No network access needed. |
| Attack Complexity (AC)   | Low (L)      | No race condition, no ASLR bypass, no timing dependency. Reliable on first attempt once strategy is tuned. |
| Privileges Required (PR) | Low (L)      | Only a regular unprivileged local account is needed. Zero sudo permissions required. |
| User Interaction (UI)    | None (N)     | The attacker runs the exploit alone — no victim interaction needed. |
| Scope (S)                | Unchanged (U)| Privilege escalation stays within the compromised system's security scope. |
| Confidentiality (C)      | High (H)     | Root access = read any file including `/etc/shadow`, SSH keys, application secrets. |
| Integrity (I)            | High (H)     | Root access = modify any file, add users, install backdoors, alter system binaries. |
| Availability (A)         | High (H)     | Root access = crash or destroy the system; delete any file; kill any process. |

**Practical severity note:** Although CVSS categorizes attack vector as "Local"
(requiring a local account), in real-world scenarios a low-privilege local
account is easily obtained via phishing, credential stuffing, web shell
compromise, or shared hosting. From that foothold, CVE-2021-3156 provides
an **immediate, reliable, single-step escalation to root** — with no
configuration dependency and no timing requirement.

---

## 12. Related sudo Vulnerabilities (Historical Context)

| CVE              | Year | Type                  | Affected sudo   | Severity | Notes                                  |
|------------------|------|-----------------------|-----------------|----------|----------------------------------------|
| **CVE-2021-3156**| 2021 | Heap BOF → LPE        | 1.8.2 – 1.9.5p1 | 7.8 HIGH | **This project (Baron Samedit)**        |
| CVE-2021-23240   | 2021 | Symlink attack         | 1.9.4p1         | 7.8 HIGH | sudoedit -s symlink follow             |
| CVE-2019-14287   | 2019 | Privilege bypass       | < 1.8.28        | 8.8 HIGH | `sudo -u#-1` root bypass — logic flaw |
| CVE-2019-18634   | 2020 | Stack BOF              | < 1.8.26        | 7.8 HIGH | pwfeedback buffer overflow             |
| CVE-2017-1000368 | 2017 | Info disclosure        | < 1.8.21        | Medium   | sudo_noexec.so bypass                  |

**Why CVE-2021-3156 is more serious than CVE-2019-14287:**
CVE-2019-14287 is a logic bypass that requires the user to already have a
specific sudoers rule (`ALL` privilege). CVE-2021-3156 requires **no**
sudoers entry — the overflow occurs before the authorization check — making
it universally exploitable against any local account.

---

## 13. Vulnerability Disclosure Timeline

| Date              | Event                                                              |
|-------------------|--------------------------------------------------------------------|
| ~2011             | Buggy escape processing code introduced in sudo 1.8.2              |
| January 13, 2021  | Qualys Research Team discovers CVE-2021-3156                       |
| January 26, 2021  | Coordinated disclosure; sudo 1.8.32 and 1.9.5p2 released          |
| January 26, 2021  | blasty releases first public C PoC (GitHub)                        |
| January 27, 2021  | worawit releases Python PoC with 3 heap strategies (GitHub)        |
| January 28, 2021  | ExploitDB entry EDB-49521 published                                |
| February 4, 2021  | Rapid7 publishes detailed heap analysis and Metasploit module       |
| February 1, 2021  | Apple releases macOS Security Update 2021-001 for the same bug     |
| 2021 onward       | CISA adds to Known Exploited Vulnerabilities (KEV) catalog         |

---

*All cross-references in this document are fully sourced in `references.md`.*
*Annotated exploit walkthrough and payload analysis in `exploit_walkthrough.md`.*
*Patch and mitigation guidance in `mitigation.md`.*
