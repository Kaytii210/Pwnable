from pwn import *

p = process('./rop')
gdb.attach(p, api=True)



p.interactive()
