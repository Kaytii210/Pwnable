**Read source code**
- As we can see there is `banned_execve()` so we can't get shell by `execve("/bin/sh", null, null)` 
-`Checksec` in gdb
```
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled # can't execute shellcode
PIE:        PIE enabled
Stripped:   No
```
- We can use open(), read(), write() method  
---  
***PWNTOOLS***
- Set context `context.arch = "amd64"` (64-bit) `"i386"`(32-bit) to generate shell code in right architecture
- Use `shellcraft.cat(filename)` (o-r-w)
- `asm` assembles the shellcode into machine code
