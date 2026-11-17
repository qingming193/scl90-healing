# -*- coding: utf-8 -*-
"""
SCL-90 Dual-Version Licensing & Protected Question Delivery Server
Supports:
1. 1,000,000 pre-generated 6-char exclusive codes (500k 'pro' + 500k 'fun') with hardware device binding
2. Zero-cost Xiaohongshu Order ID mode (P + 18 digits) with anti-fake entropy validation & hardware device binding
3. Protected question bank API (/api/questions) preventing competitor F12 scraping
4. Private Owner Dashboard (/api/owner/panel?key=KOC0802)
"""
from __future__ import annotations
import os
import re
import json
import time
import hmac
import base64
import hashlib
import sqlite3
import threading
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")
SECRET_KEY = b"scl90_dual_store_hmac_secret_2026_txl_koc0802"
OWNER_KEY = "KOC0802"
PORT = int(os.environ.get("SCL90_API_PORT", "3001"))

# Validity window: UI shows "今日24:00自动失效" to drive immediate completion & zero refunds;
# Backend grants 72 hours grace on the bound device so midnight buyers never get locked out mid-test.
VALIDITY_SECONDS = 72 * 3600
BROWSER_SWITCH_GRACE_SECONDS = 6 * 3600

# Preload question banks into memory for sub-millisecond response
with open(os.path.join(BASE_DIR, "questions_pro.json"), "r", encoding="utf-8") as f:
    QUESTIONS_PRO_BYTES = json.dumps({"success": True, "version": "pro", "questions": json.load(f)}, ensure_ascii=False).encode("utf-8")

with open(os.path.join(BASE_DIR, "questions_fun.json"), "r", encoding="utf-8") as f:
    QUESTIONS_FUN_BYTES = json.dumps({"success": True, "version": "fun", "questions": json.load(f)}, ensure_ascii=False).encode("utf-8")

DB_WRITE_LOCK = threading.Lock()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def sign_token(code: str, version: str, fp: str, exp: int) -> str:
    payload = json.dumps({"c": code, "v": version, "f": fp, "e": exp}, separators=(",", ":")).encode("utf-8")
    b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    sig = hmac.new(SECRET_KEY, b64.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    return f"{b64}.{sig}"


def verify_token(token: str, expected_version: str) -> dict | None:
    if not token or "." not in token:
        return None
    try:
        b64, sig = token.split(".", 1)
        expected_sig = hmac.new(SECRET_KEY, b64.encode("ascii"), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected_sig):
            return None
        pad = "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
        if data.get("v") != expected_version:
            return None
        if int(data.get("e", 0)) < int(time.time()):
            return None
        return data
    except Exception:
        return None


def is_valid_xhs_order_id(code: str) -> bool:
    """Validate Xiaohongshu order ID format (P + 18 digits) and reject obvious fake/sequential numbers."""
    if not re.match(r"^P[5-9]\d{17}$", code):
        return False
    digits = code[1:]
    # Reject 6+ identical consecutive digits (e.g., P888888888888888888)
    if re.search(r"(\d)\1{5}", digits):
        return False
    # Require at least 5 distinct digits
    if len(set(digits)) < 5:
        return False
    # Reject obvious ascending/descending runs
    for bad in ("1234567", "2345678", "3456789", "9876543", "8765432", "7654321", "0123456"):
        if bad in digits:
            return False
    return True


def get_ip_prefix(handler: BaseHTTPRequestHandler) -> str:
    xff = handler.headers.get("X-Forwarded-For", "")
    ip = xff.split(",")[0].strip() if xff else handler.client_address[0]
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip[:16]


class AuthAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # Quiet production logs for speed

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_raw_json(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/api/health":
            return self._send_json(200, {"ok": True, "ts": int(time.time())})

        if parsed.path == "/api/questions":
            version = (qs.get("version", [""])[0]).strip().lower()
            auth_hdr = self.headers.get("Authorization", "")
            token = auth_hdr[7:].strip() if auth_hdr.startswith("Bearer ") else (qs.get("token", [""])[0]).strip()
            if version not in ("pro", "fun"):
                return self._send_json(400, {"success": False, "message": "无效的版本参数"})
            claims = verify_token(token, version)
            if not claims:
                return self._send_json(401, {"success": False, "errorCode": "UNAUTHORIZED", "message": "授权已失效或未激活，请先输入授权码激活"})
            return self._send_raw_json(200, QUESTIONS_PRO_BYTES if version == "pro" else QUESTIONS_FUN_BYTES)

        if parsed.path == "/api/owner/panel":
            key = (qs.get("key", [""])[0]).strip()
            if key != OWNER_KEY:
                return self._send_json(403, {"success": False, "message": "Forbidden"})
            action = (qs.get("action", [""])[0]).strip()
            return self._handle_owner_panel(action)

        return self._send_json(404, {"success": False, "message": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/auth/verify":
            return self._send_json(404, {"success": False, "message": "Not Found"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                return self._send_json(400, {"success": False, "message": "请求无效"})
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return self._send_json(400, {"success": False, "message": "请求格式错误"})

        raw_code = str(payload.get("code", "")).strip().upper()
        # Strip accidental spaces or dashes copied by user
        clean_code = re.sub(r"[\s\-]+", "", raw_code)
        version = str(payload.get("version", "")).strip().lower()
        fp = str(payload.get("fp", "")).strip()[:64] or "unknown_fp"
        hw_sig = str(payload.get("hwSig", "")).strip()[:128] or "unknown_hw"
        ip_pref = get_ip_prefix(self)
        now = int(time.time())

        if version not in ("pro", "fun"):
            return self._send_json(400, {"success": False, "message": "版本参数错误"})
        if not clean_code:
            return self._send_json(200, {"success": False, "errorCode": "EMPTY", "message": "请输入您的专属授权码或订单编号"})

        # 1. Owner VIP Master Codes (Permanent, multi-device for testing)
        if clean_code == "ADMIN888" or (clean_code == "PRO88888" and version == "pro") or (clean_code == "FUN88888" and version == "fun"):
            exp = now + 30 * 86400
            tok = sign_token(clean_code, version, fp, exp)
            return self._send_json(200, {
                "success": True,
                "token": tok,
                "code": clean_code,
                "mode": "vip",
                "expiresAt": exp
            })

        # 2. 6-character Exclusive Pre-generated Code
        if len(clean_code) == 6:
            return self._verify_six_char_code(clean_code, version, fp, hw_sig, ip_pref, now)

        # 3. Zero-Cost Xiaohongshu Order ID Mode (P + 18 digits = 19 chars)
        if is_valid_xhs_order_id(clean_code):
            return self._verify_order_id(clean_code, version, fp, hw_sig, ip_pref, now)

        return self._send_json(200, {
            "success": False,
            "errorCode": "FORMAT_ERROR",
            "message": "授权码格式不正确！请输入客服发送的 6 位专属授权码（或您的小红书 P 开头 19 位订单编号）。"
        })

    def _verify_six_char_code(self, code: str, version: str, fp: str, hw_sig: str, ip_pref: str, now: int):
        with DB_WRITE_LOCK:
            conn = get_db()
            try:
                row = conn.execute(
                    "SELECT code, version, status, fp1, fp2, hw_sig, ip_prefix, activated_at, use_count FROM codes WHERE code = ?",
                    (code,)
                ).fetchone()

                if not row:
                    return self._send_json(200, {
                        "success": False,
                        "errorCode": "INVALID_CODE",
                        "message": "授权码不存在，请核对是否输错字母或数字！"
                    })

                if row["version"] != version:
                    other_name = "专业临床标准版" if row["version"] == "pro" else "牛马身心沉浸版"
                    return self._send_json(200, {
                        "success": False,
                        "errorCode": "WRONG_VERSION",
                        "message": f"该授权码属于【{other_name}】专用码，无法在当前链接使用，请打开对应测评链接激活！"
                    })

                # First activation!
                if row["status"] == 0:
                    conn.execute(
                        "UPDATE codes SET status = 1, fp1 = ?, hw_sig = ?, ip_prefix = ?, activated_at = ?, use_count = 1 WHERE code = ?",
                        (fp, hw_sig, ip_pref, now, code)
                    )
                    conn.commit()
                    exp = now + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(code, version, fp, exp),
                        "code": code,
                        "expiresAt": exp
                    })

                # Already activated -> verify expiry & device lock
                act_at = int(row["activated_at"] or now)
                if now - act_at > VALIDITY_SECONDS:
                    return self._send_json(200, {
                        "success": False,
                        "errorCode": "EXPIRED",
                        "message": "该授权码已超过有效期自动失效，如需重新测评请前往小红书店铺获取新授权码。"
                    })

                # Match primary or secondary browser on same phone
                if fp == row["fp1"] or (row["fp2"] and fp == row["fp2"]):
                    conn.execute("UPDATE codes SET use_count = use_count + 1 WHERE code = ?", (code,))
                    conn.commit()
                    exp = act_at + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(code, version, fp, exp),
                        "code": code,
                        "expiresAt": exp
                    })

                # Same physical phone switching from XHS built-in browser to Safari/Quark within grace window
                same_phone = (hw_sig != "unknown_hw" and hw_sig == row["hw_sig"] and ip_pref == row["ip_prefix"])
                if not row["fp2"] and same_phone and (now - act_at <= BROWSER_SWITCH_GRACE_SECONDS):
                    conn.execute("UPDATE codes SET fp2 = ?, use_count = use_count + 1 WHERE code = ?", (fp, code))
                    conn.commit()
                    exp = act_at + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(code, version, fp, exp),
                        "code": code,
                        "expiresAt": exp
                    })

                # Different device / scalper / shared link -> BLOCK!
                return self._send_json(200, {
                    "success": False,
                    "errorCode": "DEVICE_LOCKED",
                    "message": "该授权码已绑定首次激活的手机设备，一码仅限一人一机使用，无法多设备共用！"
                })
            finally:
                conn.close()

    def _verify_order_id(self, order_id: str, version: str, fp: str, hw_sig: str, ip_pref: str, now: int):
        with DB_WRITE_LOCK:
            conn = get_db()
            try:
                row = conn.execute(
                    "SELECT order_id, version, fp1, fp2, hw_sig, ip_prefix, activated_at, use_count FROM orders WHERE order_id = ?",
                    (order_id,)
                ).fetchone()

                if not row:
                    conn.execute(
                        "INSERT INTO orders (order_id, version, fp1, hw_sig, ip_prefix, activated_at, use_count) VALUES (?, ?, ?, ?, ?, ?, 1)",
                        (order_id, version, fp, hw_sig, ip_pref, now)
                    )
                    conn.commit()
                    exp = now + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(order_id, version, fp, exp),
                        "code": order_id,
                        "expiresAt": exp
                    })

                if row["version"] != version:
                    return self._send_json(200, {
                        "success": False,
                        "errorCode": "WRONG_VERSION",
                        "message": "该订单编号已绑定另一测评版本，一单一码无法跨店混用！"
                    })

                act_at = int(row["activated_at"] or now)
                if now - act_at > VALIDITY_SECONDS:
                    return self._send_json(200, {
                        "success": False,
                        "errorCode": "EXPIRED",
                        "message": "该订单测评授权已过有效期自动失效，如需重新测评请拍下新单。"
                    })

                if fp == row["fp1"] or (row["fp2"] and fp == row["fp2"]):
                    conn.execute("UPDATE orders SET use_count = use_count + 1 WHERE order_id = ?", (order_id,))
                    conn.commit()
                    exp = act_at + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(order_id, version, fp, exp),
                        "code": order_id,
                        "expiresAt": exp
                    })

                same_phone = (hw_sig != "unknown_hw" and hw_sig == row["hw_sig"] and ip_pref == row["ip_prefix"])
                if not row["fp2"] and same_phone and (now - act_at <= BROWSER_SWITCH_GRACE_SECONDS):
                    conn.execute("UPDATE orders SET fp2 = ?, use_count = use_count + 1 WHERE order_id = ?", (fp, order_id))
                    conn.commit()
                    exp = act_at + VALIDITY_SECONDS
                    return self._send_json(200, {
                        "success": True,
                        "token": sign_token(order_id, version, fp, exp),
                        "code": order_id,
                        "expiresAt": exp
                    })

                return self._send_json(200, {
                    "success": False,
                    "errorCode": "DEVICE_LOCKED",
                    "message": "该订单编号已绑定首次激活的手机设备，仅限本人单设备使用，无法转借或重复激活！"
                })
            finally:
                conn.close()

    def _handle_owner_panel(self, action: str):
        conn = get_db()
        try:
            today_start = int(time.time()) - (int(time.time() + 8 * 3600) % 86400)
            pro_used = conn.execute("SELECT COUNT(*) FROM codes WHERE version='pro' AND status=1").fetchone()[0]
            pro_free = conn.execute("SELECT COUNT(*) FROM codes WHERE version='pro' AND status=0").fetchone()[0]
            pro_today = conn.execute("SELECT COUNT(*) FROM codes WHERE version='pro' AND status=1 AND activated_at>=?", (today_start,)).fetchone()[0]

            fun_used = conn.execute("SELECT COUNT(*) FROM codes WHERE version='fun' AND status=1").fetchone()[0]
            fun_free = conn.execute("SELECT COUNT(*) FROM codes WHERE version='fun' AND status=0").fetchone()[0]
            fun_today = conn.execute("SELECT COUNT(*) FROM codes WHERE version='fun' AND status=1 AND activated_at>=?", (today_start,)).fetchone()[0]

            ord_pro = conn.execute("SELECT COUNT(*) FROM orders WHERE version='pro'").fetchone()[0]
            ord_fun = conn.execute("SELECT COUNT(*) FROM orders WHERE version='fun'").fetchone()[0]
            ord_today = conn.execute("SELECT COUNT(*) FROM orders WHERE activated_at>=?", (today_start,)).fetchone()[0]

            sample_pro = [r[0] for r in conn.execute("SELECT code FROM codes WHERE version='pro' AND status=0 ORDER BY code DESC LIMIT 5").fetchall()]
            sample_fun = [r[0] for r in conn.execute("SELECT code FROM codes WHERE version='fun' AND status=0 ORDER BY code DESC LIMIT 5").fetchall()]

            html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>双店数据与授权码总控台</title>
            <style>body{{font-family:-apple-system,sans-serif;background:#F6F7FB;padding:18px;max-width:560px;margin:0 auto;color:#2D3139}}
            .card{{background:#fff;border-radius:16px;padding:18px;margin-bottom:14px;box-shadow:0 4px 16px rgba(0,0,0,.05)}}
            h2{{font-size:1.2rem;margin:0 0 12px}} .row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px dashed #eee;font-size:.92rem}}
            .tag{{background:#EEF2FF;color:#4F46E5;padding:3px 8px;border-radius:6px;font-family:monospace;font-weight:700}}</style></head><body>
            <div class="card"><h2>📊 今日实时激活总览</h2>
            <div class="row"><span>1号店（专业版）今日短码激活</span><b>{pro_today} 单</b></div>
            <div class="row"><span>2号店（牛马版）今日短码激活</span><b>{fun_today} 单</b></div>
            <div class="row"><span>今日小红书订单号直验激活</span><b>{ord_today} 单</b></div></div>
            <div class="card"><h2>🏥 1号店 · 专业临床版 (/pro/)</h2>
            <div class="row"><span>6位码已用 / 剩余库存</span><b>{pro_used:,} / {pro_free:,}</b></div>
            <div class="row"><span>订单号直验累计</span><b>{ord_pro:,} 单</b></div>
            <div class="row"><span>应急备用未用码（尾部安全池）</span><span>{' '.join(f'<span class="tag">{c}</span>' for c in sample_pro)}</span></div></div>
            <div class="card"><h2>⚡ 2号店 · 牛马沉浸版 (/fun/)</h2>
            <div class="row"><span>6位码已用 / 剩余库存</span><b>{fun_used:,} / {fun_free:,}</b></div>
            <div class="row"><span>订单号直验累计</span><b>{ord_fun:,} 单</b></div>
            <div class="row"><span>应急备用未用码（尾部安全池）</span><span>{' '.join(f'<span class="tag">{c}</span>' for c in sample_fun)}</span></div></div>
            <div class="card"><h2>🔑 店主永久无限测试码（不限设备）</h2>
            <div class="row"><span>双店通用超级码</span><span class="tag">ADMIN888</span></div>
            <div class="row"><span>1号店专用测试码</span><span class="tag">PRO88888</span></div>
            <div class="row"><span>2号店专用测试码</span><span class="tag">FUN88888</span></div></div></body></html>"""
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            conn.close()


if __name__ == "__main__":
    print(f"[SCL90 Auth Server] Listening on 127.0.0.1:{PORT} ...")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), AuthAPIHandler)
    httpd.serve_forever()
