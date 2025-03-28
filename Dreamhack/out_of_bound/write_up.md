**Read source code**
- `system(command[idx]);`: can get shell => out of bounds
- `Checksec` in gdb
```
Arch:     i386
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```
- So the idea is that write `/bin/sh\x00` into name and get shell by `system(name);`.
---  
***EPLOIT***
- Get address of name (p&name)
- Get address of command (p&name)
- `read(0, name, sizeof(name));` : input `/bin/sh\x00` + address of name
- `scanf("%d", &idx);`: input position of name of array command
