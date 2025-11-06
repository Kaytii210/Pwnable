# 📓 PWN STUDY NOTES

<details>
<summary><h1>🧠 Computer Architecture + Operating System</h1></summary>
<p>

## Registers

| Register | Description                                                                |
| -------- | -------------------------------------------------------------------------- |
| `rax`    | Function return value → `rax`, `eax`, `ax`, `ah`, `al` (64/32/16/8/8 bits) |
| `rbx`    | Base register (no specific use in x64)                                     |
| `rcx`    | Counter register for loops                                                 |
| `rdx`    | Data register                                                              |
| `rsi`    | Source index (source in data movement)                                     |
| `rdi`    | Destination index (destination in data movement)                           |
| `rsp`    | Stack pointer                                                              |
| `rbp`    | Stack base pointer                                                         |

---

## User-space function calls (System V i386 ABI)

- **Arguments:** pushed **right → left** onto the stack.
  At callee entry: `[esp+4]=arg1`, `[esp+8]=arg2`, …
- **Return:** `eax` (or `edx:eax`), FP in `st(0)`
- **Callee-saved:** `ebx`, `esi`, `edi`, `ebp` (and `esp`)
- **Caller-saved:** `eax`, `ecx`, `edx`
- **Stack alignment:** ABI baseline 4 bytes; SIMD code may realign to 16 bytes in prologue.

---

## Linux i386 **syscall** convention (`int 0x80`)

- **`eax`** = syscall number.
- **Args 1–6:** `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`
- **Return:** `eax` (≥0 success; **negative** = `-errno`)
- Other regs not guaranteed preserved.

---

## Linux x86-64 **syscall** convention (`syscall` instruction)

- **`rax`** — syscall number.
- **Arguments (1–6):** `rdi, rsi, rdx, r10, r8, r9`
- **Return value:** `rax` (≥ 0 on success; **negative** value = `-errno`)
- Other registers are preserved per usual rules (`rbx, rbp, r12–r15` are callee-saved in user space).

---

## 🧱 MEMORY STRUCTURE OF LINUX PROCESS

- **Code Segment (.text):** executable code (r--x)
- **Data Segment:** initialized global/static variables (rw-)
- **BSS Segment:** uninitialized global/static variables (rw-)
- **Heap Segment:** dynamic memory allocation (rw-)
- **Stack Segment:** local variables, return addresses (rw-)
- **Extra Segment:** `fs` and `gs` (used by OS)

---

## ⚙️ ASSEMBLY BASICS

### 🔹 Opcodes

- **Data Transfer:** `mov`, `lea`
- **Arithmetic:** `inc`, `dec`, `add`, `sub`
- **Logic:** `and`, `or`, `xor`, `not`
- **Comparison:** `cmp`, `test`
- **Branch:** `jmp`, `je`, `jg`
- **Stack:** `push`, `pop`
- **Procedure:** `call`, `ret`, `leave`
- **System call:** `syscall`

### 🔹 Memory Operands

- `QWORD PTR [addr]`: 8 bytes
- `DWORD PTR [addr]`: 4 bytes
- `WORD PTR [rax]`: 2 bytes
- `BYTE PTR [rax]`: 1 byte

<h2> View more in: </h2>

- [Computer Architecture](https://www.geeksforgeeks.org/computer-organization-architecture/computer-organization-and-architecture-tutorials/)
- [Assembly](https://www.tutorialspoint.com/assembly_programming/index.htm)
- [OS](https://www.tutorialspoint.com/operating_system/index.htm)

</p>
</details>

<details>
<summary><h1>🐛 Bugs</h1></summary>
<p>

## 🐚 SHELLCODE

### 📌 Target

Call `execve("/bin/sh", NULL, NULL)` to get a shell or control flow of the program.

---

### 🧬 Syscall convention for execve(/bin/sh, 0, 0) (x86_64)

| Register | Role                                 |
| -------- | ------------------------------------ |
| `rax`    | Syscall number (`0x3b` for `execve`) |
| `rdi`    | arg0: filename (`/bin/sh`)           |
| `rsi`    | arg1: argv (NULL)                    |
| `rdx`    | arg2: envp (NULL)                    |

---

### 🔩 Shellcode (x86_64)

```asm
mov rax, 0x68732f6e69622f   ; "/bin/sh" in hex
push rax
mov rdi, rsp                ; rdi = pointer to "/bin/sh"
xor rsi, rsi                ; rsi = NULL
xor rdx, rdx                ; rdx = NULL
mov rax, 0x3b               ; rax = syscall number for execve
syscall
```

Little-endian bytes
`\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05`

---

### 🔩 Shellcode (x86)

```asm
xor eax, eax
xor ecx, ecx
xor edx, edx
add eax, 0x0b               ; syscall number for execve
xor ebx, ebx
push ebx
push 0x68732f2f             ; "//sh"
push 0x6e69622f             ; "/bin"
mov ebx, esp
int 0x80                    ; syscall
```

Little-endian bytes
`\x31\xC0\x31\xC9\x31\xD2\x83\xC0\x0B\x31\xDB\x53\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\xCD\x80`

## 💥 BUFFER OVERFLOW

### 🧵 Input functions that can overflow

#### `gets(buf)` — **do not use (removed in C11)**

- **No input length limit.**
- Reads until `'\n'`, **does not store** the newline.
- Always appends `'\0'`.
- **Extremely unsafe** → classic stack overflow.

#### `scanf("%s", buf)`

- **No input length limit.**
- Reads until `" "`, `\n`, `\t`.
- Behaves like `gets()`.

#### `scanf("%[width]s", buf)`

- Reads up to `width` characters.
- If `width > sizeof(buf) - 1` → **may overflow**.
- Does not guarantee string **null-termination** (`\0`).

#### `fgets(buf, len, stream)`

- Reads up to `len - 1` characters, always appends `\0`. If input is longer, the excess remains in `stdin`.
- If input < `len`, the remaining part is filled with `\0`.
- If input = `len`, the last byte is discarded and `\0` is added.
- May **lose data**, e.g.: 30-byte buffer → can only store 29 characters if `len = 30`.
- If there's space, stores `"\n\0"`.

#### `read(fd, buf, len)`

- Reads up to `len` bytes into `buf`.
- Returns the number of bytes read (≥ 0) or **negative** value on error.
- Does not guarantee null-termination (`\0`).
- Safe only if `len` is **less than or equal** to the sizeof(`buf`).

---

### 📌 Core Overflow types

- **Stack Overflow:** overwrite data on stack (return address, canary, ...).
- **Heap Overflow:** overwrites adjacent heap chunks/objects or allocator metadata.
- **Global/Static Overflow:** overwrites global variables or static data (`.data/.bss`).
- **Off-by-one:** overwrite one byte beyond buffer boundary, often affecting adjacent data.
- **Out-of-bounds:** access memory outside the allocated buffer.
- **Integer Overflow/Underflow:** occurs when an arithmetic operation produces a value outside the representable range of the integer type.

## 🛡️ CANARY (Stack Smashing Protector)

### 🧠 Purpose

- **Prevents buffer overflow attacks** by detecting overwrites of sensitive memory regions.
- If the canary is overwritten → program will **Segmentation fault** and terminate immediately.

---

### 🔐 Structure

- Stored at: `[rbp - 0x8]`.
- Is a sequence of **8 random bytes**, **first byte is always `\x00`**.

## 🔒 NX & ASLR

### 🚫 NX (No-eXecute)

- **Prevents Shellcode:** Blocks execution of code in memory regions not marked as executable.

---

### 🎲 ASLR (Address Space Layout Randomization)

- **Goal:** Randomly allocates addresses for stack, heap, shared libraries, ... each time the binary runs.
- **Benefit:** Makes it harder to guess addresses during exploitation.

---

### 🔧 Hook Overwrite

- **Idea:** Bypass RELRO by overwriting function pointers (like `malloc()`, `free()`, `realloc()`) with arbitrary addresses to execute malicious code.

## 📌 PIE & RELRO

### 🔀 PIE (Position-Independent Executable)

- **Goal:** Execute binary with a changing load address (base address), making exploitation harder.
- **Operation:** Each run, the binary is loaded at a random address, making address guessing more complex.

---

### 🔄 PIC (Position-Independent Code)

- **Goal:** Allows code to run correctly at any memory location.
- **Features:**
  - Does not use absolute addresses.
  - Relies on relative addresses (based on `RIP` on x86_64) for address calculations.
- **Benefit:** Increases flexibility and safety when programs are loaded at different addresses.

---

### 🔗 RELRO (RELocation Read-Only)

- **Protection:** Prevents overwriting the address table (GOT) to protect important functions from exploitation.
- **Protection levels:**
  - **No RELRO:** GOT can be overwritten, easy to exploit.
  - **Partial RELRO:** Some parts of GOT are made read-only after initialization.
  - **Full RELRO:** Entire GOT is fully protected, very hard to exploit.

## 🔄 R2L-ROP

### 📌 Basic concepts

- **r2l (Return-to-libc):** Uses `ret` to call existing libc functions, e.g.: `system("/bin/sh")`.
- **ROP (Return Oriented Programming):** Uses chains of gadgets (instructions ending with `ret`) to control program flow.
- **GOT (Global Offset Table):** Table containing addresses of libc functions (e.g.: `puts`).
- **PLT (Procedure Linkage Table):** Used to call functions via GOT.
- Call a function: func_plt -> func_got -> func_libc

---

### 🔧 Technical details

- **Padding Return Address:**

  - Return address is aligned to 16 bytes.
  - I usually add a `ret` before gadgets like `pop rdi; ret` to avoid errors due to `movaps`.

- **Finding function addresses:**

  - Typically, `system` is calculated as:  
    `system = libc_base + offset`  
    (see `readelf -s libc.so.6 | grep "system"` for exact offset)

- **Finding ROP Gadgets:**
  - Use:
    ```bash
    ROP gadget --binary filename | grep "gadget_to_find"
    #search directly in process
    pop_rdi_ret = r.find_gadget(['pop rdi', 'ret'])[0] # Find registers ex: pop rdi ; ret
    ```
    Example: find gadget `pop rdi; ret` to set argument for `system`.  
    Return to `main` to continue exploitation (`e.symbols['main']`)

---

### 📌 Example on x64

1. **Leak libc address:**

   - Use functions like `puts` to print the address stored in GOT.
   - Example: use gadget `pop rdi; ret` to put the address of `puts@got` into rdi and then call `puts(puts@got)` (This will print the address of `puts` => Leak libc).
   - Calculation:
     - `libc_base = leaked_address - puts_offset (libc.symbols['puts'])`

2. **Find address of `system` and string `/bin/sh`:**

   - `system = libc_base + system_offset`
   - `binsh = libc_base + offset_of_bin_sh`

3. **Deploy ROP:**
   - Use gadget `pop rdi; ret` to set argument for `system`.
   - Example ROP:
     ```python
     p64(pop_rdi_ret) + p64(binsh) + p64(system)
     ```

---

### 📌 Example on x86

Attack procedure on x86 may include:

1. Send data into writable area such as `/bin/sh`: `read(0, writableArea, len("/bin/sh"))`
2. Print address of read_got: `write(1, read_got, len(str(read_got)))`
3. Read new address from read_got: `read(0, read_got, len(str(read_got)))`
4. Call system with writableArea containing "/bin/sh": `system(writableArea)`

## 📏 OUT OF BOUNDS

- **Out of Bounds (OOB):** Occurs when array index is negative or exceeds array length

  => **Leak/overwrite** memory.

- **Accessing array element:**
  ```c
  &arr[k] = arr + sizeof(elem) * k
  ```

## 🔠 FORMAT STRING VULNERABILITY (FSB)

### How `printf` Works

- **`printf("%s", input)`**: Prints the string passed in `input`.
- **`printf("%s")`**: If no argument, prints the value at the first address on the stack.

### Parameter Specification with `$`

- **`printf("%30$s")`**: Prints the value of the 30th argument on the stack.
- **`printf("%6$p")`**: Prints the address (in hex with `0x`) of the 6th argument on the stack.
- **`printf("%6$x")`**: Prints the hex value of the 6th argument on the stack, without `0x`.

### Applications of Format String

- **Information leak:**  
  Use format specifiers like `%p`, `%x`, `%d`, `%*n` to leak values on the stack (addresses, numbers, ...).
- **Read memory:**  
  Use `%s` to print a string at the address referenced from the stack (e.g.: read flag).
- **Overwrite memory:**  
  Use `%n`, `%hn`, `%hhn` to write the number of printed characters to a specific address, allowing modification of variables in memory.

### Difference between 32-bit and 64-bit

- **32-bit:** Arguments are usually printed directly from the stack.
- **64-bit:**
  - First 5 arguments are passed via registers: `rsi`, `rdx`, `rcx`, `r8`, `r9`.
  - From the 6th argument onward, values are taken from the stack (e.g.: `rsp`, `rsp+0x8`, `rsp+0x10`, `rsp+0x18`).

</p>
</details>

<details>
<summary><h1>🐞 Pwndbg</h1></summary>
<p>

[Pwndbg](https://github.com/pwndbg/pwndbg) is an extension for GDB that provides many useful commands for analyzing and exploiting binaries.

[Documentation](https://pwndbg.re/pwndbg/latest/reference/pwndbg/) pwndbg reference

---

## 🔍 Some useful commands

- **`checksec`**: show security features of the binary:

  - **Canary:** anti buffer overflow (often set at `[rbp-0x8]`).
  - **NX (Non-Executable):** prevents execution of shellcode on the stack.
  - **PIE (Position Independent Executable):** Binary is loaded at a random address.
  - **RELRO (RELocation Read-Only):** Checks the protection feature of the address table (GOT). (anti GOT overwrite)

- **`start`**: run the program and stop right at the beginning of the `main` function, helping you quickly start debugging.

- **`disass <func>` (disassemble):** disassemble the specified function.

- **`vmmap`**: show virtual memory map of the process, including regions: stack, heap, libraries, and other segments, also displays their permissions, size, offsets and file paths.

- **`run`**: execute the program from the beginning.

- **`b *<address>` (break):** set a breakpoint at a specific address.

  - _Ex:_ `b *0x400123`

- **`del <breakpoint>` (delete):** delete the specified breakpoint.

- **`c` (continue):** continue executing the program until the next breakpoint or when the program stops.

- **`finish`**: continue executing until the current function ends.

- **`si` (step into):** execute the next instruction and step into any functions (if present).

- **`ni` (next instruction):** execute the next instruction but do **not** step into any functions.

- **`i` (info):** show information about the program state, for example:

  - `i r` (info registers): Information about the registers.
  - `i b` (info breakpoints): List of breakpoints.

- **`k` (kill):** kill the debugging process.

- **`bt` (backtrace):** show the call stack at the time of stopping.

- **`x` (examine):** examine memory at a specific address.

  - Form: `x/<count><format> <address>`

  | Format                 | Size                    |
  | ---------------------- | ----------------------- |
  | `x` (hexadecimal)      | `b` (Byte, 1 byte)      |
  | `o` (octal)            | `h` (Halfword, 2 bytes) |
  | `d` (decimal)          | `w` (Word, 4 bytes)     |
  | `u` (unsigned decimal) | `g` (Giant, 8 bytes)    |
  | `s` (string)           |                         |
  | `t` (binary)           |                         |
  | `f` (float)            |                         |
  | `a` (address)          |                         |
  | `c` (character)        |                         |
  | `i` (instruction)      |                         |

  - _Ex:_ `x/10wx 0x601000` shows 10 words in hex format from address `0x601000`.

- **`tel` (telescope):** show memory around the current instruction pointer, recursively explores addresses referenced by the memory to display their values. Ex:

  - `tel 0x123456 5` shows 5 lines of memory starting from address `0x123456`.

  - `tel $rsp` shows memory around the stack pointer.

- **`context`:** show an overview of the current state of the process, including registers, stack, and disassembly around the current address.

- **`heap`:** show detailed information about the heap, assisting in the analysis of heap-related vulnerabilities.

- **`vis_heap_chunks`:** visualize heap chunks, showing their metadata and contents.

- **`search`:** search for a string or byte sequence in memory.

  - _Ex:_ `search "flag"` will find all locations containing the string `"flag"`.

- **`p &<variable>` (print):** print the address of a specific variable.

  - _Ex:_ `p &0x601000` will print the value at address `0x601000`.

- **`pattern_create`** and **`pattern_offset`**

  - Useful for creating and analyzing pattern strings (cyclic patterns) to find offsets during exploitation:
    - `pattern_create 100`: Create a pattern with 100 bytes.
    - `pattern_offset <value>`: Determine the position of the `<value>` in the pattern.

- **`set detach-on-fork off`**: tells GDB to not detach from the other processes after program calls `fork()/vfork()`. Both parent and child processes will stay under GDB as separate inferiors.
  - **`set follow-fork-mode child/parent`**: process that GDB will follow after a fork.
  - **`info inferiors`**: list tracked processes.
  - **`inferior <id>`**: switch to a specific inferior process.

</p>
</details>

<details>
<summary><h1>🧰 Pwntools</h1></summary>
<p>

[PwnTools](https://github.com/Gallopsled/pwntools) is a powerful library that supports binary exploitation and automation. Here are some basic commands and techniques:

---

### 🔹 Process & Remote

```python
from pwn import *

# Start a local process
p = process('./filename')        # Local binary

# Connect to remote server
p = remote('address', port)      # Remote server

# Attach gdb for debugging (with pwntools API)
gdb.attach(p, api=True, gdbscript='''pwndbg_script''')
```

### 🔹 ELF & Libc

```python
# Load binary and libc
e = ELF('./filename')
libc = ELF('./libc.so.6')

# Get address from PLT (Procedure Linkage Table)
plt_addr = e.plt['funcname']

# Get address from GOT (Global Offset Table)
got_addr = e.got['funcname']

# Get offset of function in binary
func_offset = e.symbols['funcname']

# Get offset of function in libc (note: symbol name must be exact)
libc_func_offset = libc.symbols['funcname']

# Find location of "/bin/sh" string in libc
bin_sh = list(libc.search(b'/bin/sh'))[0]
```

### 🔹 Packing & Unpacking

```python
# Convert number to little-endian byte string (64-bit and 32-bit)
packed_64 = p64(0xdeadbeef)
packed_32 = p32(0xdeadbeef)

# Unpack byte string to integer (64-bit and 32-bit)
number_64 = u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')
number_32 = u32(b'\xef\xbe\xad\xde')
```

### 🔹 Sending and receiving data

```python
# Send data
p.send(b'A')                      # Send 1 byte 'A'
p.sendline(b'A')                  # Send 'A' + '\n'

# Send data after receiving prompt
p.sendafter(b'hello', b'A')
p.sendlineafter(b'hello', b'A')

#send and sendline
send: read
sendline: scanf, gets, fgets

# Receive data
data = p.recv(1024)               # Receive up to 1024 bytes
line = p.recvline()               # Receive until newline
exact = p.recvn(5)                # Receive exactly 5 bytes
until = p.recvuntil(b'hello')     # Receive until 'hello' is found
all_data = p.recvall()            # Receive all data until process ends
```

### 🔹 Shellcode

```python
# Shellcode
shellcode = asm(''''
    ;write your shellcode here
    mov rax, 0x3b               ; syscall number for execve
    mov rdi, rsp                ; rdi = pointer to "/bin/sh"
    xor rsi, rsi                ; rsi = NULL
    xor rdx, rdx                ; rdx = NULL
    syscall
''')
```

### 🔹 Otherwise, use pwntools built-in shellcode generation:

```python
# Spawn a shell (execve /bin/sh)
shellcode = shellcraft.sh()

# Generate shellcode to read and print 'flag.txt'
shellcode = shellcraft.readfile('flag.txt')

# Open, read and write
shellcode = shellcraft.open('flag.txt')
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)

#Finnally, assemble the shellcode
shellcode = asm(shellcode)
```

Visit [here](https://docs.pwntools.com/en/stable/shellcraft.html) for more shellcode examples.

Remember to use `context.arch = 'amd64' or 'i386'` to set the architecture before generating shellcode.

### 🔹 Format string

```python
# Write value to address using format string
fmtstr_payload(
    offset,
    writes,
    numbwritten: int = 0,
    write_size: str = 'byte',
    write_size_max: str = 'long',
    overflows: int = 16,
    strategy: str = "small",
    badbytes: frozenset = frozenset(),
    offset_bytes: int = 0,
    no_dollars: bool = False
)
#Ex: write one_gadget to read_got
offset = 5 # Check in gdb
where  = read_got
what   = one_gadget
payload = fmtstr_payload(offset, { where: what })
```

### 🔹 Print & Interactive

```python
# Print info to console
log.info("Useful info" + info)
log.success("Success info" + info)
log.warning("Warning info" + info)

# Switch to interactive mode to interact directly with process
p.interactive()
```

## Other commands can be found in the [official documentation](https://docs.pwntools.com/en/stable/) / [cheat sheet](https://gist.github.com/KnightChaser/e0ddb74278de522c6e2973d1ae8135e6).

</p>
</details>

<details>
<summary><h1>🔗 Pwninit</h1></summary>
<p>

[Pwninit](https://github.com/io12/pwninit) is a tool for patching binaries with provided libc and loader.

---

Commands:

- `pwninit`: auto patch file
- `mv file_patch file`: rename file

</p>
</details>

<details>
<summary><h1>🛠️ Other useful tools</h1></summary>
<p>

- [CyberChef](https://gchq.github.io/CyberChef/) : tool for analyzing and decoding data

- [LinuxSyscallReference](https://syscalls.mebeim.net/?table=x86/64/x64/latest) : tool for looking up Linux syscalls and their parameters

- [Online Assembler/Disassembler](https://defuse.ca/online-x86-assembler.htm) : tool for assembling and disassembling x86/x64

- [Shell-storm](https://shell-storm.org/online/Online-Assembler-and-Disassembler/) : tool for converting.

- [Libc Database](https://libc.rip/) : tool for searching libc versions based on leaked addresses

</p>
</details>

<details>
<summary><h1>🔰 Learning resources</h1></summary>
<p>

- [Dream Hack](https://dreamhack.io/)

- [Heap](https://github.com/shellphish/how2heap)

- [Azeria Labs](https://azeria-labs.com/writing-arm-shellcode/)

- [JHTPwner](https://www.youtube.com/@JHTPwner)

- [Leonardo](https://www.youtube.com/@leonardo69696)

- [Naetw](https://github.com/Naetw/CTF-pwn-tips)

- [Nobody](https://github.com/nobodyisnobody)

- [Midas](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)

- [Nightmare](https://guyinatuxedo.github.io/)

</p>
</details>
