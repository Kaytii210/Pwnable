**Read source code**
- `binsh`: PIE not enable -> useful
- `system("echo 'system@plt");`: add system to plt => ret2plt
- `read(0, buf, 0x100);` bufferoverflow => leak canary
- Stack
```
buf (rbp - 0x48)
canary (rbp-0x8)
ret
pop rdi_ret
binsh
system
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
- So the idea is that use system("/bin/sh")
---  
- Note: 
  + When leak canary, canary have `\x00` at the end, with little-endian architecture so byte `\x00` at the start of the canary, so when printf meet `\x00`
and stop print => can't leak canary like that.  
  => Solution: `\x00` + bytes leak.
  + Error cause by movaps: need 16 bytes at ret
