# 🛠️ PWN STUDY NOTES

## 🧠 COMPUTER ARCHITECTURE

| Register | Description |
|----------|-------------|
| `rax`    | Return value of a function → `rax`, `eax`, `ax`, `ah`, `al` (64/32/16/8/8) |
| `rbx`    | Base register (no specific use in x64) |
| `rcx`    | Counter register for loops |
| `rdx`    | Data register |
| `rsi`    | Source index (source in data movement) |
| `rdi`    | Destination index (destination in data movement) |
| `rsp`    | Stack pointer |
| `rbp`    | Stack base pointer |

---

## 🧱 MEMORY STRUCTURE OF LINUX PROCESS

- **Code Segment (.text)**: executable code (r--x)
- **Data Segment**: initialized global/static vars (rw-)
- **BSS Segment**: uninitialized global/static vars (rw-)
- **Heap Segment**: dynamic memory allocation (rw-)
- **Stack Segment**: local vars, return addresses (rw-)
- **Extra Segment**: `fs` and `gs` (used by OS)

---

## ⚙️ ASSEMBLY BASICS

### 🔹 Opcodes

- **Data Transfer**: `mov`, `lea`
- **Arithmetic**: `inc`, `dec`, `add`, `sub`
- **Logic**: `and`, `or`, `xor`, `not`
- **Comparison**: `cmp`, `test`
- **Branch**: `jmp`, `je`, `jg`
- **Stack**: `push`, `pop`
- **Procedure**: `call`, `ret`, `leave`
- **System call**: `syscall`

### 🔹 Memory Operands

- `QWORD PTR [addr]`: 8 bytes
- `DWORD PTR [addr]`: 4 bytes
- `WORD PTR [rax]`: 2 bytes

---

## 🐚 SHELLCODE

### 📌 Mục tiêu
Gọi `execve("/bin/sh", NULL, NULL)` để thực thi shell.

---

### 🧬 Syscall Convention (x86_64)

| Register | Vai trò |
|----------|---------|
| `rax`    | Syscall number (`0x3b` cho `execve`) |
| `rdi`    | arg0: filename (`/bin/sh`) |
| `rsi`    | arg1: argv (NULL) |
| `rdx`    | arg2: envp (NULL) |

---

### 🔩 Shellcode (x86_64)

```asm
mov rax, 0x68732f6e69622f   ; "/bin/sh" in hex
push rax
mov rdi, rsp                ; rdi = pointer to "/bin/sh"
xor rsi, rsi                ; rsi = NULL
xor rdx, rdx                ; rdx = NULL
mov rax, 0x3b               ; rax = syscall number for execve
syscall```


