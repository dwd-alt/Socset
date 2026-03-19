"""
Kildear Social Network — Security-Hardened Version
Enhanced with multi-layer DDoS/DoS protection, intrusion detection,
adaptive IP blocking, bot filtering, and comprehensive security hardening.
"""

import os
import re
import time
import uuid
import html
import hashlib
import logging
import platform
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from ipaddress import ip_address, ip_network, AddressValueError

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, abort, session, send_from_directory, g)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func, and_, text
import bcrypt

# ──────────────────────────────────────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)
security_logger = logging.getLogger("security")

# ──────────────────────────────────────────────────────────────────────────────
#  Environment
# ──────────────────────────────────────────────────────────────────────────────
is_production = os.environ.get('RENDER') == 'true' or os.environ.get('FLASK_ENV') == 'production'
is_render     = os.environ.get('RENDER') == 'true'
is_windows    = platform.system() == 'Windows'
basedir       = os.path.abspath(os.path.dirname(__file__))

# ──────────────────────────────────────────────────────────────────────────────
#  Flask App
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Database
if is_render:
    _db_url = os.environ.get('DATABASE_URL', '')
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = _db_url + ('&' if '?' in _db_url else '?') + 'sslmode=require'
else:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'kildear.db')

UPLOAD_FOLDER = (os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
                 if is_render else os.path.join('static', 'uploads'))

UPLOAD_SUBFOLDERS = [
    'avatars', 'images', 'videos', 'covers', 'groups',
    'channels', 'chat_images', 'group_covers', 'channel_covers', 'voice_messages'
]

ALLOWED_IMAGE = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_VIDEO = {"mp4", "webm", "mov", "avi", "mkv"}
ALLOWED_AUDIO = {"mp3", "wav", "ogg", "m4a"}

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(48).hex()),
    SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_size": 10,
        "max_overflow": 20,
    } if is_render else {},
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024)),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    REMEMBER_COOKIE_DURATION=timedelta(days=14),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=is_production,
    SESSION_REFRESH_EACH_REQUEST=True,
    SEND_FILE_MAX_AGE_DEFAULT=0,
)

db         = SQLAlchemy(app)
csrf       = CSRFProtect(app)
login_mgr  = LoginManager(app)
login_mgr.login_view = "login"
login_mgr.login_message = "Пожалуйста, войдите для доступа к этой странице."
login_mgr.login_message_category = "info"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute", "2000 per hour"],
    storage_uri="memory://",
)

async_mode = 'threading' if is_windows else 'eventlet'
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode=async_mode,
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=10_000_000,
)


# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY ENGINE  —  Multi-layer DDoS / DoS / Intrusion Protection
# ══════════════════════════════════════════════════════════════════════════════

class SecurityEngine:
    """
    Layered attack-mitigation system:

      Layer 1 — IP Reputation (permanent + temporary bans)
      Layer 2 — Rate / Velocity Control (sliding-window per IP)
      Layer 3 — Slowloris / Connection Flood Detection
      Layer 4 — Login Brute-Force & Credential-Stuffing Protection
      Layer 5 — Payload Inspection (oversized, malformed, SQLi/XSS probes)
      Layer 6 — Bot / Scanner Fingerprinting
      Layer 7 — Adaptive Auto-unban (cooldown after clean traffic)
    """

    # ── tuneable constants ────────────────────────────────────────────────────
    WINDOW_SECONDS        = 10       # sliding window for rate checks
    HARD_LIMIT_WINDOW     = 200      # max requests in WINDOW_SECONDS → hard ban
    SOFT_LIMIT_WINDOW     = 80       # requests in WINDOW_SECONDS → temp throttle
    THROTTLE_DURATION     = 60       # seconds to throttle a soft-limit IP
    TEMP_BAN_DURATION     = 600      # 10 min for first offence
    PERM_BAN_THRESHOLD    = 5        # offences before permanent ban
    LOGIN_FAIL_WINDOW     = 300      # 5 min window for login failures
    LOGIN_FAIL_LIMIT      = 10       # max failures before account-level lockout
    SUSPICIOUS_UA_SCORE   = 3        # score added for suspicious user-agent
    PAYLOAD_SCORE         = 5        # score for malicious payload patterns
    BAN_SCORE_THRESHOLD   = 10       # cumulative score triggers temp ban
    CLEAN_TRAFFIC_UNBAN   = 3600     # seconds of clean traffic → auto-unban temp
    MAX_HEADER_SIZE       = 8192     # bytes; requests with larger headers → ban
    MAX_URI_LENGTH        = 2048     # chars

    # Known attack tool / scanner user-agent substrings
    BAD_UA_PATTERNS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'dirbuster',
        'gobuster', 'wfuzz', 'hydra', 'medusa', 'burpsuite', 'acunetix',
        'nessus', 'openvas', 'python-requests/2.1', 'go-http-client/1.1',
        'curl/7.1', 'libwww-perl', 'jakarta commons', 'wget/1.1',
        'havij', 'pangolin', 'beef/', 'metasploit',
    ]

    # SQLi / XSS / path-traversal probe patterns
    MALICIOUS_PATTERNS = [
        re.compile(p, re.I) for p in [
            r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
            r"exec\s*\(|xp_cmdshell|information_schema)",
            r"(<script[\s>]|javascript:|vbscript:|on\w+=)",
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)",
            r"(eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\()",
            r"(\bor\b\s+['\"0-9]|'\s*;\s*--|/\*.*\*/)",
        ]
    ]

    # Trusted CIDR ranges (loopback + RFC-1918 private)
    TRUSTED_NETWORKS = [
        ip_network("127.0.0.0/8"),
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("::1/128"),
    ]

    def __init__(self):
        self._lock              = threading.Lock()
        # {ip: deque of timestamps}  — sliding request windows
        self._req_log           = defaultdict(lambda: deque(maxlen=500))
        # {ip: {'until': timestamp, 'reason': str}}
        self._temp_bans         = {}
        # {ip} — permanent bans (survive restarts only in memory; persist to DB for prod)
        self._perm_bans         = set()
        # {ip: int}  — offence counter
        self._offence_count     = defaultdict(int)
        # {ip: float} — last time IP was throttled
        self._throttled_until   = {}
        # {ip: float} — score accumulator for adaptive scoring
        self._threat_score      = defaultdict(float)
        # {ip: deque of timestamps} — login failure log
        self._login_fail_log    = defaultdict(lambda: deque(maxlen=50))
        # {ip: float} — when IP last had clean traffic (for auto-unban)
        self._last_clean        = defaultdict(float)
        # {ip: float} — first-seen timestamp (for connection-flood detection)
        self._first_seen        = {}
        # {ip: int}  — concurrent request estimate (simple counter)
        self._concurrent        = defaultdict(int)

        # Background janitor thread
        t = threading.Thread(target=self._janitor, daemon=True)
        t.start()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_trusted(self, ip_str: str) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in net for net in self.TRUSTED_NETWORKS)
        except (ValueError, AddressValueError):
            return False

    def _temp_ban(self, ip: str, reason: str, duration: int = None):
        dur = duration or self.TEMP_BAN_DURATION
        self._offence_count[ip] += 1
        if self._offence_count[ip] >= self.PERM_BAN_THRESHOLD:
            self._perm_bans.add(ip)
            security_logger.warning(f"[PERM BAN] {ip} — {reason} "
                                    f"(offences: {self._offence_count[ip]})")
        else:
            self._temp_bans[ip] = {
                'until': time.time() + dur,
                'reason': reason,
            }
            security_logger.warning(f"[TEMP BAN {dur}s] {ip} — {reason} "
                                    f"(offence #{self._offence_count[ip]})")

    def _score(self, ip: str, points: float, reason: str):
        self._threat_score[ip] += points
        if self._threat_score[ip] >= self.BAN_SCORE_THRESHOLD:
            self._temp_ban(ip, f"threat score exceeded ({reason})")
            self._threat_score[ip] = 0

    # ── Layer 1: IP Reputation ────────────────────────────────────────────────

    def is_banned(self, ip: str) -> bool:
        if ip in self._perm_bans:
            return True
        entry = self._temp_bans.get(ip)
        if entry:
            if time.time() < entry['until']:
                return True
            else:
                del self._temp_bans[ip]           # ban expired
        return False

    # ── Layer 2: Velocity / Rate ──────────────────────────────────────────────

    def check_rate(self, ip: str) -> bool:
        """Returns True if request is allowed, False if it must be dropped."""
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        q = self._req_log[ip]
        # Evict old timestamps
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        count = len(q)

        if count > self.HARD_LIMIT_WINDOW:
            self._temp_ban(ip, f"hard rate limit exceeded ({count} req/{self.WINDOW_SECONDS}s)")
            return False

        if count > self.SOFT_LIMIT_WINDOW:
            self._throttled_until[ip] = now + self.THROTTLE_DURATION
            self._score(ip, 2, "soft rate limit")

        throttle_exp = self._throttled_until.get(ip, 0)
        if now < throttle_exp:
            return False  # throttled, drop silently

        self._last_clean[ip] = now
        return True

    # ── Layer 3: Slowloris / Connection Flood ─────────────────────────────────

    def track_concurrent(self, ip: str, delta: int):
        self._concurrent[ip] += delta
        if self._concurrent[ip] > 50:
            self._temp_ban(ip, f"connection flood ({self._concurrent[ip]} concurrent)")

    # ── Layer 4: Login Brute-Force ────────────────────────────────────────────

    def record_login_failure(self, ip: str, username: str = ""):
        now = time.time()
        cutoff = now - self.LOGIN_FAIL_WINDOW
        q = self._login_fail_log[ip]
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        count = len(q)
        self._score(ip, 1.5, f"login failure ({username})")
        if count >= self.LOGIN_FAIL_LIMIT:
            self._temp_ban(ip, f"brute-force / cred stuffing ({count} failures)",
                           duration=1800)
        security_logger.info(f"[LOGIN FAIL] {ip} user={username!r} count={count}")

    def record_login_success(self, ip: str):
        self._login_fail_log[ip].clear()
        # Partial score decay on successful login
        self._threat_score[ip] = max(0, self._threat_score[ip] - 3)

    # ── Layer 5: Payload Inspection ───────────────────────────────────────────

    def inspect_request(self, req) -> bool:
        """Returns True if the request looks safe, False otherwise."""
        # URI length
        if len(req.full_path) > self.MAX_URI_LENGTH:
            return False

        # Header size approximation
        header_size = sum(len(k) + len(v) for k, v in req.headers)
        if header_size > self.MAX_HEADER_SIZE:
            return False

        # Probe patterns in URI + query-string + common form fields
        targets = [req.full_path]
        for field in ('username', 'email', 'content', 'q', 'search'):
            val = req.args.get(field) or req.form.get(field)
            if val:
                targets.append(val)

        for target in targets:
            for pattern in self.MALICIOUS_PATTERNS:
                if pattern.search(target):
                    return False
        return True

    # ── Layer 6: Bot / Scanner Fingerprinting ─────────────────────────────────

    def score_user_agent(self, ip: str, ua: str):
        if not ua:
            self._score(ip, 2, "empty user-agent")
            return
        ua_lower = ua.lower()
        for bad in self.BAD_UA_PATTERNS:
            if bad in ua_lower:
                self._temp_ban(ip, f"known attack tool UA: {bad}")
                return
        # Suspiciously short UA
        if len(ua) < 10:
            self._score(ip, self.SUSPICIOUS_UA_SCORE, "suspiciously short UA")

    # ── Layer 7: Janitor (auto-cleanup & adaptive unban) ─────────────────────

    def _janitor(self):
        """Background thread: clean stale state every 60 s."""
        while True:
            time.sleep(60)
            try:
                now = time.time()
                with self._lock:
                    # Expire temp bans
                    expired = [ip for ip, v in self._temp_bans.items()
                               if now >= v['until']]
                    for ip in expired:
                        del self._temp_bans[ip]
                        security_logger.info(f"[AUTO UNBAN] {ip} — ban expired")

                    # Adaptive score decay: reduce by 1 point / min for quiet IPs
                    for ip in list(self._threat_score.keys()):
                        if self._threat_score[ip] > 0:
                            self._threat_score[ip] = max(
                                0, self._threat_score[ip] - 1)

                    # Clean old request logs for IPs with no traffic
                    stale_ips = [ip for ip, q in self._req_log.items()
                                 if not q or now - q[-1] > 600]
                    for ip in stale_ips:
                        del self._req_log[ip]

                    # Reset concurrent counter for IPs that have been idle
                    for ip in list(self._concurrent.keys()):
                        if self._concurrent[ip] <= 0:
                            del self._concurrent[ip]

            except Exception as exc:
                security_logger.error(f"[JANITOR ERROR] {exc}")

    # ── Public API ────────────────────────────────────────────────────────────

    def process_request(self, req) -> tuple[bool, int]:
        """
        Full pipeline check.  Returns (allowed: bool, http_status: int).
        Call this at the top of before_request.
        """
        ip = _get_client_ip()

        # Trusted networks bypass ALL checks
        if self._is_trusted(ip):
            return True, 200

        # Layer 1 — IP reputation
        if self.is_banned(ip):
            return False, 429

        # Layer 6 — UA scoring (cheap, do early)
        ua = req.headers.get('User-Agent', '')
        self.score_user_agent(ip, ua)

        # Re-check after UA scoring (might have triggered a ban)
        if self.is_banned(ip):
            return False, 403

        # Layer 2 — Rate
        if not self.check_rate(ip):
            return False, 429

        # Layer 5 — Payload
        if not self.inspect_request(req):
            self._score(ip, self.PAYLOAD_SCORE, "malicious payload")
            security_logger.warning(f"[PAYLOAD] {ip} {req.method} {req.full_path[:120]}")
            return False, 400

        return True, 200

    def ban_ip(self, ip: str, reason: str = "manual ban", permanent: bool = False):
        """Admin-triggered ban."""
        if permanent:
            self._perm_bans.add(ip)
        else:
            self._temp_ban(ip, reason)

    def unban_ip(self, ip: str):
        """Admin-triggered unban."""
        self._perm_bans.discard(ip)
        self._temp_bans.pop(ip, None)
        self._offence_count.pop(ip, None)
        self._threat_score[ip] = 0
        security_logger.info(f"[MANUAL UNBAN] {ip}")

    def get_stats(self) -> dict:
        return {
            "temp_banned":   len(self._temp_bans),
            "perm_banned":   len(self._perm_bans),
            "throttled":     sum(1 for t in self._throttled_until.values() if t > time.time()),
            "tracked_ips":   len(self._req_log),
            "top_offenders": sorted(
                self._offence_count.items(), key=lambda x: x[1], reverse=True
            )[:10],
        }


# Singleton instance
security = SecurityEngine()


# ──────────────────────────────────────────────────────────────────────────────
#  IP Resolution Helper
# ──────────────────────────────────────────────────────────────────────────────

def _get_client_ip() -> str:
    """Robust IP extraction that respects reverse-proxy headers."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        # Take the leftmost (client) IP, strip whitespace
        candidate = forwarded.split(',')[0].strip()
        try:
            ip_address(candidate)  # validate
            return candidate
        except (ValueError, AddressValueError):
            pass
    real_ip = request.headers.get('X-Real-IP', '')
    if real_ip:
        try:
            ip_address(real_ip)
            return real_ip
        except (ValueError, AddressValueError):
            pass
    return request.remote_addr or '0.0.0.0'


# ──────────────────────────────────────────────────────────────────────────────
#  Before / After Request Hooks
# ──────────────────────────────────────────────────────────────────────────────

@app.before_request
def before_request_hook():
    ip = _get_client_ip()
    g.client_ip = ip
    security.track_concurrent(ip, +1)

    allowed, status = security.process_request(request)
    if not allowed:
        security.track_concurrent(ip, -1)
        if status == 429:
            abort(429)
        elif status == 403:
            abort(403)
        elif status == 400:
            abort(400)
        else:
            abort(status)


@app.after_request
def after_request_hook(response):
    ip = getattr(g, 'client_ip', None)
    if ip:
        security.track_concurrent(ip, -1)

    # ── Security headers ─────────────────────────────────────────────────────
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]       = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    if is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

    csp_parts = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "font-src 'self' https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "connect-src 'self' wss: ws:",
        "worker-src 'self' blob:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_parts)

    # Remove server fingerprinting
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)

    return response


# ──────────────────────────────────────────────────────────────────────────────
#  Template Filters
# ──────────────────────────────────────────────────────────────────────────────

@app.template_filter('timeago')
def timeago_filter(date):
    if not date:
        return 'recently'
    diff = datetime.utcnow() - date
    if diff.days > 365:   return f"{diff.days // 365}y ago"
    if diff.days > 30:    return f"{diff.days // 30}mo ago"
    if diff.days > 0:     return f"{diff.days}d ago"
    if diff.seconds > 3600: return f"{diff.seconds // 3600}h ago"
    if diff.seconds > 60: return f"{diff.seconds // 60}m ago"
    return "just now"


@app.template_filter('format_date')
def format_date_filter(date, fmt='%b %d, %Y'):
    return date.strftime(fmt) if date else ''


@app.template_filter('format_time')
def format_time_filter(date, fmt='%H:%M'):
    return date.strftime(fmt) if date else ''


# ──────────────────────────────────────────────────────────────────────────────
#  Decorators
# ──────────────────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE MODELS
# ══════════════════════════════════════════════════════════════════════════════

follows = db.Table(
    "follows",
    db.Column("follower_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("followed_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
)
post_likes = db.Table(
    "post_likes",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("post_id", db.Integer, db.ForeignKey("post.id"), primary_key=True),
)
group_members = db.Table(
    "group_members",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
)
channel_subs = db.Table(
    "channel_subs",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("channel_id", db.Integer, db.ForeignKey("channel.id"), primary_key=True),
)
blocks = db.Table(
    "blocks",
    db.Column("blocker_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("blocked_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(40), unique=True, nullable=False)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)
    display_name    = db.Column(db.String(60), default="")
    bio             = db.Column(db.String(500), default="")
    avatar          = db.Column(db.String(300), default="/static/default_avatar.png")
    cover_photo     = db.Column(db.String(300), default="")
    website         = db.Column(db.String(200), default="")
    location        = db.Column(db.String(100), default="")
    accent_color    = db.Column(db.String(7), default="#6c63ff")
    is_private      = db.Column(db.Boolean, default=False)
    is_verified     = db.Column(db.Boolean, default=False)
    is_banned       = db.Column(db.Boolean, default=False)
    is_admin        = db.Column(db.Boolean, default=False)
    is_online       = db.Column(db.Boolean, default=False)
    last_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret  = db.Column(db.String(32), nullable=True)
    # Security — track failed logins at account level too
    failed_logins   = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

    posts          = db.relationship("Post", backref="author", lazy="dynamic",
                                     foreign_keys="Post.user_id")
    sent_msgs      = db.relationship("Message", backref="sender", lazy="dynamic",
                                     foreign_keys="Message.sender_id")
    recv_msgs      = db.relationship("Message", backref="receiver", lazy="dynamic",
                                     foreign_keys="Message.receiver_id")
    notifications  = db.relationship("Notification", backref="recipient", lazy="dynamic",
                                     foreign_keys="Notification.user_id")
    comments       = db.relationship("Comment", backref="author", lazy="dynamic")
    owned_groups   = db.relationship("Group", backref="owner", lazy="dynamic")
    owned_channels = db.relationship("Channel", backref="owner", lazy="dynamic")
    login_history  = db.relationship("LoginHistory", backref="user", lazy="dynamic")

    blocked_users = db.relationship(
        "User", secondary=blocks,
        primaryjoin=blocks.c.blocker_id == id,
        secondaryjoin=blocks.c.blocked_id == id,
        backref=db.backref("blocked_by", lazy="dynamic"),
        lazy="dynamic",
    )
    following = db.relationship(
        "User", secondary=follows,
        primaryjoin=follows.c.follower_id == id,
        secondaryjoin=follows.c.followed_id == id,
        backref=db.backref("followers", lazy="dynamic"),
        lazy="dynamic",
    )

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    def is_account_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def record_failed_login(self):
        self.failed_logins = (self.failed_logins or 0) + 1
        if self.failed_logins >= 5:
            minutes = min(2 ** (self.failed_logins - 5) * 5, 60)
            self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)

    def reset_failed_logins(self):
        self.failed_logins = 0
        self.locked_until  = None

    def is_following(self, user):
        return self.following.filter(follows.c.followed_id == user.id).count() > 0

    def is_blocked(self, user):
        return self.blocked_users.filter(blocks.c.blocked_id == user.id).count() > 0

    def block(self, user):
        if not self.is_blocked(user):
            self.blocked_users.append(user)
            return True
        return False

    def unblock(self, user):
        if self.is_blocked(user):
            self.blocked_users.remove(user)
            return True
        return False

    @property
    def follower_count(self):  return self.followers.count()
    @property
    def following_count(self): return self.following.count()
    @property
    def post_count(self):      return self.posts.count()


class LoginHistory(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    ip_address  = db.Column(db.String(45), nullable=False)
    user_agent  = db.Column(db.String(200))
    location    = db.Column(db.String(100))
    success     = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class VoiceMessage(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    sender_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    audio_url   = db.Column(db.String(300), nullable=False)
    duration    = db.Column(db.Integer, default=0)
    is_read     = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    sender   = db.relationship("User", foreign_keys=[sender_id],   backref="sent_voice_msgs")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_voice_msgs")


class Call(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    caller_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    callee_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    call_type  = db.Column(db.String(10), nullable=False)
    status     = db.Column(db.String(20), default='missed')
    duration   = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at   = db.Column(db.DateTime, nullable=True)
    caller = db.relationship("User", foreign_keys=[caller_id])
    callee = db.relationship("User", foreign_keys=[callee_id])


class Report(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    reporter_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    post_id          = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    comment_id       = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=True)
    reason           = db.Column(db.String(200), nullable=False)
    description      = db.Column(db.Text)
    status           = db.Column(db.String(20), default='pending')
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at      = db.Column(db.DateTime, nullable=True)
    reviewed_by      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reporter      = db.relationship("User", foreign_keys=[reporter_id])
    reported_user = db.relationship("User", foreign_keys=[reported_user_id])
    reviewer      = db.relationship("User", foreign_keys=[reviewed_by])


class Post(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content    = db.Column(db.Text, default="")
    media_url  = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    thumbnail  = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views      = db.Column(db.Integer, default=0)

    liked_by = db.relationship("User", secondary=post_likes,
                               backref="liked_posts", lazy="dynamic")
    comments = db.relationship("Comment", backref="post", lazy="dynamic",
                               cascade="all,delete")

    @property
    def like_count(self):    return self.liked_by.count()
    @property
    def comment_count(self): return self.comments.count()
    def is_liked_by(self, user): return self.liked_by.filter(
        post_likes.c.user_id == user.id).count() > 0


class Comment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    post_id    = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    sender_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content     = db.Column(db.Text, default="")
    media_url   = db.Column(db.String(300), default="")
    is_read     = db.Column(db.Boolean, default=False)
    is_deleted  = db.Column(db.Boolean, default=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    replies = db.relationship("Message",
                              backref=db.backref("reply_to", remote_side=[id]))


class Group(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    slug        = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar      = db.Column(db.String(300), default="/static/default_group.png")
    cover       = db.Column(db.String(300), default="")
    owner_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_private  = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    members = db.relationship("User", secondary=group_members,
                              backref="groups", lazy="dynamic")
    posts   = db.relationship("GroupPost", backref="group", lazy="dynamic",
                              cascade="all,delete")
    @property
    def member_count(self): return self.members.count()


class GroupPost(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    group_id   = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content    = db.Column(db.Text, default="")
    media_url  = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author     = db.relationship("User")


class Channel(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    slug        = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar      = db.Column(db.String(300), default="/static/default_channel.png")
    cover       = db.Column(db.String(300), default="")
    owner_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_nsfw     = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    subscribers = db.relationship("User", secondary=channel_subs,
                                  backref="subscribed_channels", lazy="dynamic")
    posts = db.relationship("ChannelPost", backref="channel", lazy="dynamic",
                            cascade="all,delete")
    @property
    def sub_count(self): return self.subscribers.count()


class ChannelPost(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey("channel.id"), nullable=False)
    content    = db.Column(db.Text, default="")
    media_url  = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    views      = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    type         = db.Column(db.String(30), nullable=False)
    post_id      = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    call_id      = db.Column(db.Integer, db.ForeignKey("call.id"), nullable=True)
    text         = db.Column(db.String(300), default="")
    is_read      = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    from_user = db.relationship("User", foreign_keys=[from_user_id])
    call      = db.relationship("Call", foreign_keys=[call_id])


# ──────────────────────────────────────────────────────────────────────────────
#  Notification Helpers
# ──────────────────────────────────────────────────────────────────────────────

def notification_link(notif):
    if notif.type in ('like', 'comment', 'mention') and notif.post_id:
        return url_for('view_post', post_id=notif.post_id)
    if notif.type == 'follow' and notif.from_user:
        return url_for('profile', username=notif.from_user.username)
    if notif.type in ('missed_call', 'incoming_call', 'voice_message') and notif.from_user:
        return url_for('chat', username=notif.from_user.username)
    return '#'


def notification_icon(notif):
    return {
        'like': '❤️', 'comment': '💬', 'follow': '👤', 'mention': '@',
        'group_post': '👥', 'channel_post': '📢', 'missed_call': '📞',
        'incoming_call': '📞', 'voice_message': '🎤', 'message': '💬',
    }.get(notif.type, '🔔')


def notification_text(notif):
    if notif.text:
        return notif.text
    name = notif.from_user.username if notif.from_user else "Someone"
    return {
        'like':         f"{name} liked your post",
        'comment':      f"{name} commented on your post",
        'follow':       f"{name} started following you",
        'mention':      f"{name} mentioned you in a post",
        'group_post':   "New post in group",
        'channel_post': "New post in channel",
        'missed_call':  f"Missed call from {name}",
        'voice_message': f"Voice message from {name}",
        'message':      f"New message from {name}",
    }.get(notif.type, "New notification")


# ──────────────────────────────────────────────────────────────────────────────
#  File Helpers
# ──────────────────────────────────────────────────────────────────────────────

def allowed_file(filename: str, allowed: set) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def ensure_upload_folders():
    for folder in UPLOAD_SUBFOLDERS:
        path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            logger.error(f"Cannot create upload folder {path}: {e}")


def save_file(file, subfolder: str):
    if not file or not file.filename:
        return None
    try:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        all_allowed = ALLOWED_IMAGE | ALLOWED_VIDEO | ALLOWED_AUDIO
        if ext not in all_allowed:
            return None
        filename = f"{uuid.uuid4().hex}.{ext}"
        dest = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(dest, exist_ok=True)
        path = os.path.join(dest, filename)
        file.save(path)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return None
        prefix = "/uploads" if is_render else "/static/uploads"
        return f"{prefix}/{subfolder}/{filename}"
    except Exception as e:
        logger.error(f"save_file error: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  Auth Loader & Context Processor
# ──────────────────────────────────────────────────────────────────────────────

@login_mgr.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_globals():
    unread = notif_count = 0
    stats = {}
    if current_user.is_authenticated:
        unread = Message.query.filter_by(
            receiver_id=current_user.id, is_read=False, is_deleted=False).count()
        notif_count = Notification.query.filter_by(
            user_id=current_user.id, is_read=False).count()
        if current_user.is_admin:
            stats['total_reports']        = Report.query.filter_by(status='pending').count()
            stats['pending_verification'] = User.query.filter_by(is_verified=False, is_banned=False).count()
            stats['banned_users']         = User.query.filter_by(is_banned=True).count()
    return dict(
        unread_messages=unread,
        notif_count=notif_count,
        stats=stats,
        csrf_token=generate_csrf,
        notification_link=notification_link,
        notification_icon=notification_icon,
        notification_text=notification_text,
        now=datetime.utcnow(),
        is_production=is_production,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ─── Uploads / Static ────────────────────────────────────────────────────────

@app.route('/uploads/<path:subfolder>/<path:filename>')
def serve_upload(subfolder, filename):
    if subfolder not in UPLOAD_SUBFOLDERS:
        abort(404)
    directory = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
    if not os.path.exists(os.path.join(directory, filename)):
        abort(404)
    return send_from_directory(directory, filename)


@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ─── API / Notifications ─────────────────────────────────────────────────────

@app.route("/api/unread_counts")
@login_required
def unread_counts():
    return jsonify({
        "notifications": Notification.query.filter_by(
            user_id=current_user.id, is_read=False).count(),
        "messages": Message.query.filter_by(
            receiver_id=current_user.id, is_read=False, is_deleted=False).count(),
        "voice_messages": VoiceMessage.query.filter_by(
            receiver_id=current_user.id, is_read=False).count(),
    })


@app.route("/api/mark_notification_read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    n = Notification.query.filter_by(id=notif_id, user_id=current_user.id).first()
    if n:
        n.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Not found"}), 404


@app.route("/api/mark_all_notifications_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"success": True})


# ─── Admin ────────────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    stats = {
        "total_users":    User.query.count(),
        "total_posts":    Post.query.count(),
        "total_comments": Comment.query.count(),
        "total_reports":  Report.query.filter_by(status='pending').count(),
        "new_users_today": User.query.filter(
            User.created_at >= datetime.utcnow().date()).count(),
        "banned_users":   User.query.filter_by(is_banned=True).count(),
    }
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_users=User.query.order_by(User.created_at.desc()).limit(10).all(),
        pending_reports=Report.query.filter_by(status='pending')
            .order_by(Report.created_at.desc()).limit(20).all(),
        recent_logins=LoginHistory.query.order_by(
            LoginHistory.created_at.desc()).limit(20).all(),
    )


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    page   = request.args.get("page", 1, type=int)
    search = request.args.get("search", "")
    q = User.query
    if search:
        pat = f"%{search}%"
        q = q.filter(or_(User.username.ilike(pat), User.email.ilike(pat),
                         User.display_name.ilike(pat)))
    users = q.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template("admin/users.html", users=users, search=search)


@app.route("/admin/user/<int:user_id>/toggle-ban", methods=["POST"])
@login_required
@admin_required
def admin_toggle_ban(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot ban yourself", "error")
        return redirect(url_for("admin_users"))
    user.is_banned = not user.is_banned
    db.session.commit()
    flash(f"User {user.username} {'banned' if user.is_banned else 'unbanned'}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot change your own admin rights", "error")
        return redirect(url_for("admin_users"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"User {user.username} {'granted' if user.is_admin else 'revoked'} admin", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/toggle-verify", methods=["POST"])
@login_required
@admin_required
def admin_toggle_verify(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()
    flash(f"User {user.username} verification toggled", "success")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot delete yourself", "error")
        return redirect(url_for("admin_users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"User {username} deleted", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/reports")
@login_required
@admin_required
def admin_reports():
    status  = request.args.get("status", "pending")
    q = Report.query if status == "all" else Report.query.filter_by(status=status)
    return render_template("admin/reports.html",
                           reports=q.order_by(Report.created_at.desc()).all(),
                           current_status=status)


@app.route("/admin/report/<int:report_id>/review", methods=["POST"])
@login_required
@admin_required
def admin_review_report(report_id):
    report = Report.query.get_or_404(report_id)
    action = request.form.get("action")
    if action == "dismiss":
        report.status = "dismissed"
        flash("Report dismissed", "success")
    elif action == "approve":
        report.status = "reviewed"
        if report.reported_user_id:
            u = User.query.get(report.reported_user_id)
            if u:
                u.is_banned = True
                flash(f"User {u.username} banned", "success")
    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_user.id
    db.session.commit()
    return redirect(url_for("admin_reports"))


@app.route("/admin/verification")
@login_required
@admin_required
def admin_verification():
    page  = request.args.get("page", 1, type=int)
    users = User.query.filter_by(is_verified=False, is_banned=False)\
                .order_by(User.created_at.desc()).paginate(page=page, per_page=20)
    return render_template("admin/verification.html", users=users)


@app.route("/admin/banned")
@login_required
@admin_required
def admin_banned():
    page  = request.args.get("page", 1, type=int)
    users = User.query.filter_by(is_banned=True)\
                .order_by(User.last_seen.desc()).paginate(page=page, per_page=20)
    return render_template("admin/banned.html", users=users)


@app.route("/admin/admins")
@login_required
@admin_required
def admin_admins():
    return render_template("admin/admins.html",
                           admins=User.query.filter_by(is_admin=True)
                                   .order_by(User.created_at).all())


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    page = request.args.get("page", 1, type=int)
    logs = LoginHistory.query.order_by(LoginHistory.created_at.desc())\
                       .paginate(page=page, per_page=50)
    return render_template("admin/logs.html", logs=logs)


# ── Admin Security Dashboard ──────────────────────────────────────────────────

@app.route("/admin/security")
@login_required
@admin_required
def admin_security():
    """Real-time security engine stats visible only to admins."""
    return jsonify(security.get_stats())


@app.route("/admin/security/ban", methods=["POST"])
@login_required
@admin_required
def admin_security_ban():
    data = request.get_json(force=True)
    ip   = data.get("ip", "").strip()
    permanent = bool(data.get("permanent", False))
    if not ip:
        return jsonify({"error": "IP required"}), 400
    security.ban_ip(ip, reason=f"Manual ban by {current_user.username}", permanent=permanent)
    return jsonify({"success": True})


@app.route("/admin/security/unban", methods=["POST"])
@login_required
@admin_required
def admin_security_unban():
    data = request.get_json(force=True)
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    security.unban_ip(ip)
    return jsonify({"success": True})


# ─── Report Routes ────────────────────────────────────────────────────────────

@app.route("/report/user/<int:user_id>", methods=["GET", "POST"])
@login_required
def report_user(user_id):
    reported = User.query.get_or_404(user_id)
    if reported.id == current_user.id:
        flash("Cannot report yourself", "error")
        return redirect(url_for("profile", username=reported.username))
    if request.method == "POST":
        reason = request.form.get("reason")
        if not reason:
            flash("Reason required", "error")
            return redirect(url_for("report_user", user_id=user_id))
        db.session.add(Report(
            reporter_id=current_user.id,
            reported_user_id=reported.id,
            reason=reason,
            description=request.form.get("description", ""),
        ))
        db.session.commit()
        flash(f"Report submitted for {reported.username}", "success")
        return redirect(url_for("profile", username=reported.username))
    reasons = [("spam","Spam"),("harassment","Harassment"),
               ("hate_speech","Hate Speech"),("violence","Violence"),
               ("scam","Scam"),("fake_account","Fake Account"),("other","Other")]
    return render_template("report_user.html", user=reported, reasons=reasons)


@app.route("/report/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def report_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id == current_user.id:
        flash("Cannot report your own post", "error")
        return redirect(url_for("view_post", post_id=post_id))
    if request.method == "POST":
        reason = request.form.get("reason")
        if not reason:
            flash("Reason required", "error")
            return redirect(url_for("report_post", post_id=post_id))
        db.session.add(Report(
            reporter_id=current_user.id,
            reported_user_id=post.user_id,
            post_id=post.id,
            reason=reason,
            description=request.form.get("description", ""),
        ))
        db.session.commit()
        flash("Report submitted", "success")
        return redirect(url_for("view_post", post_id=post_id))
    reasons = [("spam","Spam"),("harassment","Harassment"),
               ("hate_speech","Hate Speech"),("violence","Violence"),
               ("nsfw","Inappropriate Content"),("copyright","Copyright"),("other","Other")]
    return render_template("report_post.html", post=post, reasons=reasons)


@app.route("/report/comment/<int:comment_id>", methods=["GET", "POST"])
@login_required
def report_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == current_user.id:
        flash("Cannot report your own comment", "error")
        return redirect(url_for("view_post", post_id=comment.post_id))
    if request.method == "POST":
        reason = request.form.get("reason")
        if not reason:
            flash("Reason required", "error")
            return redirect(url_for("report_comment", comment_id=comment_id))
        db.session.add(Report(
            reporter_id=current_user.id,
            reported_user_id=comment.user_id,
            comment_id=comment.id,
            reason=reason,
            description=request.form.get("description", ""),
        ))
        db.session.commit()
        flash("Report submitted", "success")
        return redirect(url_for("view_post", post_id=comment.post_id))
    return render_template("report_comment.html", comment=comment)


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        if not all([username, email, password]):
            flash("All fields are required", "error")
            return render_template("register.html")
        if not re.match(r"^[a-zA-Z0-9_]{3,40}$", username):
            flash("Username must be 3-40 chars: letters, digits, underscores", "error")
            return render_template("register.html")
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Invalid email format", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match", "error")
            return render_template("register.html")

        existing = User.query.filter(
            (User.username == username) | (User.email == email)).first()
        if existing:
            flash("Username or email already taken", "error")
            return render_template("register.html")

        try:
            user = User(username=username, email=email, display_name=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)
            flash(f"Welcome to Kildear, {username}! 🎉", "success")
            return redirect(url_for("index"))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Register error: {e}")
            flash("Registration error. Please try again.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password   = request.form.get("password", "")
        remember   = bool(request.form.get("remember"))
        ip         = _get_client_ip()
        ua         = request.headers.get('User-Agent', '')

        user = User.query.filter(
            or_(func.lower(User.username) == identifier.lower(),
                func.lower(User.email)    == identifier.lower())
        ).first()

        success = False
        if user:
            # Account-level lockout (exponential backoff)
            if user.is_account_locked():
                remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
                flash(f"Account locked. Try again in {remaining} minutes.", "error")
                return render_template("login.html")

            if user.check_password(password) and not user.is_banned:
                user.reset_failed_logins()
                user.is_online  = True
                user.last_seen  = datetime.utcnow()
                login_user(user, remember=remember)
                session.permanent = remember
                security.record_login_success(ip)
                success = True
                flash(f"Welcome back, {user.username}! 👋", "success")
            else:
                user.record_failed_login()
                db.session.commit()
                security.record_login_failure(ip, identifier)
                flash("Invalid credentials.", "error")
        else:
            security.record_login_failure(ip, identifier)
            flash("Invalid credentials.", "error")

        try:
            db.session.add(LoginHistory(
                user_id=user.id if user else None,
                ip_address=ip,
                user_agent=ua[:200],
                success=success,
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

        if success:
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ─── Feed ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    page         = request.args.get("page", 1, type=int)
    followed_ids = [u.id for u in current_user.following.all()] + [current_user.id]
    blocked_ids  = [b.id for b in current_user.blocked_users]
    posts = (Post.query
             .filter(Post.user_id.in_(followed_ids))
             .filter(Post.user_id.notin_(blocked_ids))
             .order_by(Post.created_at.desc())
             .paginate(page=page, per_page=15, error_out=False))
    suggestions = (User.query
                   .filter(User.id.notin_(followed_ids + blocked_ids))
                   .filter(User.id != current_user.id)
                   .order_by(func.random()).limit(5).all())
    return render_template("index.html", posts=posts, suggestions=suggestions)


# ─── Posts ────────────────────────────────────────────────────────────────────

@app.route("/post/create", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_post():
    content    = request.form.get("content", "").strip()
    media_file = request.files.get("media")
    media_url  = ""
    media_type = "text"

    if media_file and media_file.filename:
        ext = media_file.filename.rsplit(".", 1)[-1].lower() if '.' in media_file.filename else ''
        if ext in ALLOWED_VIDEO:
            media_url  = save_file(media_file, "videos") or ""
            media_type = "video"
        elif ext in ALLOWED_IMAGE:
            media_url  = save_file(media_file, "images") or ""
            media_type = "image"
        else:
            flash("Unsupported file type", "error")
            return redirect(url_for("index"))

    if not content and not media_url:
        flash("Post cannot be empty", "error")
        return redirect(url_for("index"))

    db.session.add(Post(user_id=current_user.id, content=content,
                        media_url=media_url, media_type=media_type))
    db.session.commit()
    flash("Post published!", "success")
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>")
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author.id in [b.id for b in current_user.blocked_users]:
        abort(403)
    post.views += 1
    db.session.commit()
    return render_template("post_detail.html", post=post,
                           comments=post.comments.order_by(Comment.created_at.asc()).all())


@app.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author.id in [b.id for b in current_user.blocked_users]:
        return jsonify({"error": "Blocked"}), 403
    if post.is_liked_by(current_user):
        post.liked_by.remove(current_user)
        liked = False
    else:
        post.liked_by.append(current_user)
        liked = True
        if post.user_id != current_user.id:
            db.session.add(Notification(
                user_id=post.user_id, from_user_id=current_user.id,
                type="like", post_id=post.id,
                text=f"{current_user.username} liked your post."))
            _emit_notification(post.user_id, {
                "type": "like",
                "from_user": {"id": current_user.id, "username": current_user.username,
                              "avatar": current_user.avatar},
                "post_id": post.id, "text": f"{current_user.username} liked your post",
            })
    db.session.commit()
    return jsonify({"liked": liked, "count": post.like_count})


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author.id in [b.id for b in current_user.blocked_users]:
        return jsonify({"error": "Blocked"}), 403
    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"error": "Comment cannot be empty"}), 400
    c = Comment(post_id=post.id, user_id=current_user.id, content=content)
    db.session.add(c)
    if post.user_id != current_user.id:
        db.session.add(Notification(
            user_id=post.user_id, from_user_id=current_user.id,
            type="comment", post_id=post.id,
            text=f"{current_user.username} commented on your post."))
    db.session.commit()
    return jsonify({"id": c.id, "username": current_user.username,
                    "avatar": current_user.avatar, "content": c.content,
                    "created_at": c.created_at.strftime("%b %d, %Y")})


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted.", "info")
    return redirect(url_for("index"))


# ─── Profile ──────────────────────────────────────────────────────────────────

@app.route("/u/<username>")
@login_required
def profile(username):
    user       = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()
    is_blocked = current_user.is_blocked(user) if user.id != current_user.id else False
    page       = request.args.get("page", 1, type=int)
    tab        = request.args.get("tab", "posts")
    posts = videos = []
    if not is_blocked:
        posts  = user.posts.order_by(Post.created_at.desc()).paginate(
                     page=page, per_page=12, error_out=False)
        videos = user.posts.filter_by(media_type="video")\
                     .order_by(Post.created_at.desc()).limit(12).all()
    return render_template("profile.html", user=user, posts=posts, videos=videos,
                           is_own=(user.id == current_user.id),
                           is_following=current_user.is_following(user) if user.id != current_user.id else False,
                           is_blocked=is_blocked, tab=tab)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        try:
            current_user.display_name = request.form.get("display_name", "")[:60]
            current_user.bio          = request.form.get("bio", "")[:500]
            current_user.website      = request.form.get("website", "")[:200]
            current_user.location     = request.form.get("location", "")[:100]
            current_user.accent_color = request.form.get("accent_color", "#6c63ff")[:7]
            current_user.is_private   = bool(request.form.get("is_private"))

            for field, subfolder, max_mb in [("avatar", "avatars", 5), ("cover_photo", "covers", 10)]:
                f = request.files.get("cover_photo" if field == "cover_photo" else field)
                if f and f.filename:
                    f.seek(0, 2); size = f.tell(); f.seek(0)
                    if size > max_mb * 1024 * 1024:
                        flash(f"File too large (max {max_mb} MB)", "error")
                    else:
                        url = save_file(f, subfolder)
                        if url:
                            setattr(current_user, field, url)
            db.session.commit()
            flash("Profile updated!", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"edit_profile error: {e}")
            flash("Error updating profile", "error")
        return redirect(url_for("profile", username=current_user.username))
    return render_template("edit_profile.html")


@app.route("/follow/<username>", methods=["POST"])
@login_required
def follow(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()
    if user.id == current_user.id:
        return jsonify({"error": "Cannot follow yourself"}), 400
    if current_user.is_blocked(user):
        return jsonify({"error": "Cannot follow blocked user"}), 400
    if current_user.is_following(user):
        current_user.following.remove(user)
        following = False
    else:
        current_user.following.append(user)
        following = True
        db.session.add(Notification(
            user_id=user.id, from_user_id=current_user.id, type="follow",
            text=f"{current_user.username} started following you."))
    db.session.commit()
    return jsonify({"following": following, "followers": user.follower_count})


# ─── Block / Unblock ─────────────────────────────────────────────────────────

@app.route("/user/<int:user_id>/block", methods=["POST"])
@login_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({"error": "Cannot block yourself"}), 400
    if current_user.block(user):
        for u in [current_user, user]:
            other = user if u is current_user else current_user
            if u.is_following(other):
                u.following.remove(other)
        db.session.commit()
        return jsonify({"success": True, "blocked": True})
    return jsonify({"error": "Already blocked"}), 400


@app.route("/user/<int:user_id>/unblock", methods=["POST"])
@login_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.unblock(user):
        db.session.commit()
        return jsonify({"success": True, "blocked": False})
    return jsonify({"error": "Not blocked"}), 400


# ─── Video ────────────────────────────────────────────────────────────────────

@app.route("/video")
@login_required
def video_feed():
    page        = request.args.get("page", 1, type=int)
    blocked_ids = [b.id for b in current_user.blocked_users]
    videos = (Post.query.filter_by(media_type="video")
              .filter(Post.user_id.notin_(blocked_ids))
              .order_by(Post.created_at.desc())
              .paginate(page=page, per_page=10, error_out=False))
    return render_template("video.html", videos=videos)


# ─── Search ───────────────────────────────────────────────────────────────────

@app.route("/search")
@login_required
@limiter.limit("60 per minute")
def search():
    q   = request.args.get("q", "").strip().lstrip('@')
    tab = request.args.get("tab", "people")
    users = posts = groups = channels = []
    blocked_ids = [b.id for b in current_user.blocked_users]
    if q:
        p = f"%{q}%"
        users    = User.query.filter(or_(User.username.ilike(p),
                                         User.display_name.ilike(p)))\
                             .filter(User.id != current_user.id)\
                             .filter(User.id.notin_(blocked_ids)).limit(20).all()
        posts    = Post.query.filter(Post.content.ilike(p))\
                             .filter(Post.user_id.notin_(blocked_ids)).limit(20).all()
        groups   = Group.query.filter(or_(Group.name.ilike(p),
                                          Group.description.ilike(p))).limit(10).all()
        channels = Channel.query.filter(or_(Channel.name.ilike(p),
                                            Channel.description.ilike(p))).limit(10).all()

    if request.args.get("ajax") == "1" or \
       request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"users": [
            {"id": u.id, "username": u.username,
             "display_name": u.display_name or u.username,
             "avatar": u.avatar or "/static/default_avatar.png",
             "is_online": u.is_online} for u in users
        ]})
    return render_template("search.html", q=q, tab=tab,
                           users=users, posts=posts,
                           groups=groups, channels=channels)


# ─── Chat ─────────────────────────────────────────────────────────────────────

@app.route("/chat")
@login_required
def chat_list():
    try:
        sent_to   = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set   = ({r[0] for r in sent_to} | {r[0] for r in recv_from}) \
                    - {b.id for b in current_user.blocked_users}

        conversations = []
        for p in User.query.filter(User.id.in_(uid_set)).all():
            last = (Message.query
                    .filter(or_(and_(Message.sender_id == current_user.id,
                                     Message.receiver_id == p.id),
                                and_(Message.sender_id == p.id,
                                     Message.receiver_id == current_user.id)))
                    .filter_by(is_deleted=False)
                    .order_by(Message.created_at.desc()).first())
            unread = Message.query.filter_by(
                sender_id=p.id, receiver_id=current_user.id,
                is_read=False, is_deleted=False).count()
            voice_unread = VoiceMessage.query.filter_by(
                sender_id=p.id, receiver_id=current_user.id, is_read=False).count()
            conversations.append({"user": p, "last": last,
                                  "unread": unread, "voice_unread": voice_unread})

        conversations.sort(key=lambda x: x["last"].created_at if x["last"] else datetime.min,
                           reverse=True)
        return render_template("chat_list.html", conversations=conversations)
    except Exception as e:
        logger.error(f"chat_list error: {e}")
        flash("Error loading chat", "error")
        return redirect(url_for("index"))


@app.route("/chat/<username>")
@login_required
def chat(username):
    try:
        partner    = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()
        is_blocked = current_user.is_blocked(partner)

        if not is_blocked:
            Message.query.filter_by(sender_id=partner.id, receiver_id=current_user.id,
                                    is_read=False).update({"is_read": True})
            VoiceMessage.query.filter_by(sender_id=partner.id, receiver_id=current_user.id,
                                         is_read=False).update({"is_read": True})
            db.session.commit()

        messages = voice_messages = []
        if not is_blocked:
            messages = (Message.query
                        .filter(or_(and_(Message.sender_id == current_user.id,
                                         Message.receiver_id == partner.id),
                                    and_(Message.sender_id == partner.id,
                                         Message.receiver_id == current_user.id)))
                        .filter_by(is_deleted=False)
                        .order_by(Message.created_at.asc()).limit(100).all())
            voice_messages = (VoiceMessage.query
                              .filter(or_(and_(VoiceMessage.sender_id == current_user.id,
                                               VoiceMessage.receiver_id == partner.id),
                                          and_(VoiceMessage.sender_id == partner.id,
                                               VoiceMessage.receiver_id == current_user.id)))
                              .order_by(VoiceMessage.created_at.asc()).limit(50).all())

        sent_to   = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set   = ({r[0] for r in sent_to} | {r[0] for r in recv_from}) \
                    - {b.id for b in current_user.blocked_users}

        conversations = []
        for p in User.query.filter(User.id.in_(uid_set)).all():
            last = (Message.query
                    .filter(or_(and_(Message.sender_id == current_user.id,
                                     Message.receiver_id == p.id),
                                and_(Message.sender_id == p.id,
                                     Message.receiver_id == current_user.id)))
                    .filter_by(is_deleted=False)
                    .order_by(Message.created_at.desc()).first())
            unread = Message.query.filter_by(
                sender_id=p.id, receiver_id=current_user.id,
                is_read=False, is_deleted=False).count()
            conversations.append({"user": p, "last": last, "unread": unread})

        conversations.sort(key=lambda x: x["last"].created_at if x["last"] else datetime.min,
                           reverse=True)
        return render_template("chat.html", partner=partner, messages=messages,
                               voice_messages=voice_messages,
                               conversations=conversations, is_blocked=is_blocked)
    except Exception as e:
        logger.error(f"chat error: {e}")
        flash("Error loading chat", "error")
        return redirect(url_for("chat_list"))


@app.route("/chat/<username>/send", methods=["POST"])
@login_required
@limiter.limit("120 per minute")
def send_message(username):
    try:
        partner = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()
        if current_user.is_blocked(partner):
            return jsonify({"error": "Cannot send to blocked user"}), 403

        content    = request.form.get("content", "").strip()
        media_file = request.files.get("media")
        media_url  = save_file(media_file, "chat_images") or "" if media_file and media_file.filename else ""
        reply_to   = request.form.get("reply_to", type=int)

        if not content and not media_url:
            return jsonify({"error": "Message cannot be empty"}), 400

        msg = Message(sender_id=current_user.id, receiver_id=partner.id,
                      content=content, media_url=media_url, reply_to_id=reply_to)
        db.session.add(msg)
        db.session.add(Notification(user_id=partner.id, from_user_id=current_user.id,
                                    type="message",
                                    text=f"{current_user.username} sent you a message"))
        db.session.commit()

        message_data = {
            "id": msg.id, "sender_id": current_user.id,
            "sender_username": current_user.username,
            "sender_avatar": current_user.avatar,
            "content": msg.content, "media_url": msg.media_url,
            "reply_to_id": msg.reply_to_id,
            "created_at": msg.created_at.strftime("%H:%M"),
        }
        room = "_".join(sorted([str(current_user.id), str(partner.id)]))
        socketio.emit("new_message", message_data, room=room)
        _emit_notification(partner.id, {"type": "message",
                                        "from_user": {"id": current_user.id,
                                                      "username": current_user.username,
                                                      "avatar": current_user.avatar},
                                        "text": f"New message from {current_user.username}"})
        return jsonify({"ok": True, "id": msg.id})
    except Exception as e:
        logger.error(f"send_message error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/chat/message/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403
    msg.is_deleted = True
    db.session.commit()
    return jsonify({"success": True})


# ─── Voice ────────────────────────────────────────────────────────────────────

@app.route("/voice/send", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def send_voice_message():
    try:
        receiver_id = request.form.get("receiver_id", type=int)
        audio_file  = request.files.get("audio")
        if not audio_file or not audio_file.filename:
            return jsonify({"error": "No audio file"}), 400
        receiver = User.query.get_or_404(receiver_id)
        if current_user.is_blocked(receiver):
            return jsonify({"error": "Blocked"}), 403

        ext = audio_file.filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_AUDIO:
            return jsonify({"error": "Unsupported audio format"}), 400

        filename  = f"voice_{uuid.uuid4().hex}.{ext}"
        dest      = os.path.join(app.config['UPLOAD_FOLDER'], 'voice_messages')
        os.makedirs(dest, exist_ok=True)
        audio_file.save(os.path.join(dest, filename))

        vm = VoiceMessage(
            sender_id=current_user.id, receiver_id=receiver.id,
            audio_url=f"/uploads/voice_messages/{filename}",
            duration=request.form.get("duration", 0, type=int),
        )
        db.session.add(vm)
        db.session.add(Notification(user_id=receiver.id, from_user_id=current_user.id,
                                    type="voice_message",
                                    text=f"Voice message from {current_user.username}"))
        db.session.commit()

        room = "_".join(sorted([str(current_user.id), str(receiver.id)]))
        socketio.emit("new_voice_message", {
            "id": vm.id, "sender_id": current_user.id,
            "sender_username": current_user.username,
            "sender_avatar": current_user.avatar,
            "audio_url": vm.audio_url, "duration": vm.duration,
            "created_at": vm.created_at.strftime("%H:%M"),
        }, room=room)
        return jsonify({"success": True, "id": vm.id})
    except Exception as e:
        logger.error(f"send_voice_message error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/voice/<int:message_id>")
@login_required
def get_voice_message(message_id):
    msg = VoiceMessage.query.get_or_404(message_id)
    if msg.sender_id != current_user.id and msg.receiver_id != current_user.id:
        abort(403)
    return jsonify({"id": msg.id, "sender_id": msg.sender_id,
                    "audio_url": msg.audio_url, "duration": msg.duration,
                    "created_at": msg.created_at.isoformat(), "is_read": msg.is_read})


@app.route("/voice/mark-read/<int:message_id>", methods=["POST"])
@login_required
def mark_voice_read(message_id):
    msg = VoiceMessage.query.get_or_404(message_id)
    if msg.receiver_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403
    msg.is_read = True
    db.session.commit()
    return jsonify({"success": True})


# ─── Calls ────────────────────────────────────────────────────────────────────

WEBRTC_ICE = {'iceServers': [
    {'urls': 'stun:stun.l.google.com:19302'},
    {'urls': 'stun:stun1.l.google.com:19302'},
    {'urls': 'stun:stun2.l.google.com:19302'},
]}


@app.route("/call/start", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def start_call():
    try:
        data      = request.get_json()
        callee    = User.query.get_or_404(data.get('callee_id'))
        call_type = data.get('type', 'audio')
        if current_user.is_blocked(callee):
            return jsonify({"error": "Blocked"}), 403
        call = Call(caller_id=current_user.id, callee_id=callee.id,
                    call_type=call_type, status='ongoing')
        db.session.add(call)
        db.session.commit()
        socketio.emit("incoming_call", {
            "call_id": call.id, "caller_id": current_user.id,
            "caller_username": current_user.username,
            "caller_avatar": current_user.avatar,
            "type": call_type, "webrtc_config": WEBRTC_ICE,
        }, room=f"user_{callee.id}")
        return jsonify({"success": True, "call_id": call.id, "webrtc_config": WEBRTC_ICE})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/call/<int:call_id>/accept", methods=["POST"])
@login_required
def accept_call(call_id):
    call = Call.query.get_or_404(call_id)
    if call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403
    call.status = 'ongoing'; call.started_at = datetime.utcnow()
    db.session.commit()
    socketio.emit("call_accepted", {"call_id": call.id, "accepted_by": current_user.id},
                  room=f"user_{call.caller_id}")
    return jsonify({"success": True})


@app.route("/call/<int:call_id>/reject", methods=["POST"])
@login_required
def reject_call(call_id):
    call = Call.query.get_or_404(call_id)
    if call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403
    call.status = 'rejected'; call.ended_at = datetime.utcnow()
    db.session.commit()
    socketio.emit("call_rejected", {"call_id": call.id, "rejected_by": current_user.id},
                  room=f"user_{call.caller_id}")
    return jsonify({"success": True})


@app.route("/call/<int:call_id>/end", methods=["POST"])
@login_required
def end_call(call_id):
    call = Call.query.get_or_404(call_id)
    if call.caller_id != current_user.id and call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403
    call.status = 'completed'; call.ended_at = datetime.utcnow()
    if call.started_at:
        call.duration = (call.ended_at - call.started_at).seconds
    db.session.commit()
    other_id = call.caller_id if call.callee_id == current_user.id else call.callee_id
    socketio.emit("call_ended", {"call_id": call.id, "ended_by": current_user.id,
                                 "duration": call.duration},
                  room=f"user_{other_id}")
    return jsonify({"success": True})


@app.route("/call/history")
@login_required
def call_history():
    calls = Call.query.filter(or_(Call.caller_id == current_user.id,
                                  Call.callee_id == current_user.id))\
                      .order_by(Call.started_at.desc()).limit(50).all()
    result = []
    for c in calls:
        other_id = c.caller_id if c.callee_id == current_user.id else c.callee_id
        other    = User.query.get(other_id)
        if other:
            result.append({
                "id": c.id,
                "other_user": {"id": other.id, "username": other.username,
                               "display_name": other.display_name, "avatar": other.avatar},
                "type": c.call_type, "status": c.status, "duration": c.duration,
                "started_at": c.started_at.isoformat(),
                "is_outgoing": c.caller_id == current_user.id,
            })
    return jsonify({"calls": result})


# ─── Groups ───────────────────────────────────────────────────────────────────

@app.route("/groups")
@login_required
def groups():
    return render_template("groups.html",
                           my_groups=current_user.groups,
                           explore=Group.query.filter(
                               ~Group.members.any(User.id == current_user.id))
                           .order_by(Group.created_at.desc()).limit(20).all())


@app.route("/groups/create", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour")
def create_group():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        slug = re.sub(r"[^a-z0-9-]", "", name.lower().replace(" ", "-"))[:50] \
               + f"-{uuid.uuid4().hex[:6]}"
        g = Group(name=name, slug=slug,
                  description=request.form.get("description", "").strip()[:500],
                  owner_id=current_user.id,
                  is_private=bool(request.form.get("is_private")))
        for field, subfolder in [("avatar", "groups"), ("cover", "group_covers")]:
            f = request.files.get(field)
            if f and f.filename:
                url = save_file(f, subfolder)
                if url: setattr(g, field, url)
        db.session.add(g); db.session.flush()
        g.members.append(current_user)
        db.session.commit()
        flash(f"Group '{name}' created!", "success")
        return redirect(url_for("group_detail", slug=g.slug))
    return render_template("create_group.html")


@app.route("/groups/<slug>")
@login_required
def group_detail(slug):
    g         = Group.query.filter_by(slug=slug).first_or_404()
    is_member = g.members.filter(User.id == current_user.id).count() > 0
    return render_template("group_detail.html", group=g, is_member=is_member,
                           posts=g.posts.order_by(GroupPost.created_at.desc()).limit(30).all())


@app.route("/groups/<slug>/join", methods=["POST"])
@login_required
def join_group(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()
    if not g.members.filter(User.id == current_user.id).count():
        g.members.append(current_user); db.session.commit()
        flash(f"Joined '{g.name}'", "success")
    else:
        flash("Already a member", "info")
    return redirect(url_for("group_detail", slug=slug))


@app.route("/groups/<slug>/leave", methods=["POST"])
@login_required
def leave_group(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()
    if g.owner_id == current_user.id:
        flash("Owner cannot leave", "error")
    elif g.members.filter(User.id == current_user.id).count():
        g.members.remove(current_user); db.session.commit()
        flash(f"Left '{g.name}'", "info")
    return redirect(url_for("group_detail", slug=slug))


@app.route("/groups/<slug>/post", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def group_post(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()
    if not g.members.filter(User.id == current_user.id).count():
        abort(403)
    content = request.form.get("content", "").strip()
    media_file = request.files.get("media")
    media_url = media_type = ""
    if media_file and media_file.filename:
        ext = media_file.filename.rsplit(".", 1)[-1].lower()
        subfolder = "videos" if ext in ALLOWED_VIDEO else "images"
        media_url  = save_file(media_file, subfolder) or ""
        media_type = "video" if ext in ALLOWED_VIDEO else "image"
    p = GroupPost(group_id=g.id, user_id=current_user.id,
                  content=content, media_url=media_url, media_type=media_type or "text")
    db.session.add(p)
    for member in g.members:
        if member.id != current_user.id:
            db.session.add(Notification(user_id=member.id, from_user_id=current_user.id,
                                        type="group_post", text=f"New post in {g.name}"))
    db.session.commit()
    flash("Post published in group!", "success")
    return redirect(url_for("group_detail", slug=slug))


# ─── Channels ────────────────────────────────────────────────────────────────

@app.route("/channels")
@login_required
def channels():
    return render_template("channels.html",
                           my_channels=current_user.subscribed_channels,
                           explore=Channel.query.filter(
                               ~Channel.subscribers.any(User.id == current_user.id))
                           .order_by(Channel.created_at.desc()).limit(20).all())


@app.route("/channels/create", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour")
def create_channel():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        slug = re.sub(r"[^a-z0-9-]", "", name.lower().replace(" ", "-"))[:50] \
               + f"-{uuid.uuid4().hex[:6]}"
        c = Channel(name=name, slug=slug,
                    description=request.form.get("description", "").strip()[:500],
                    owner_id=current_user.id)
        for field, subfolder in [("avatar", "channels"), ("cover", "channel_covers")]:
            f = request.files.get(field)
            if f and f.filename:
                url = save_file(f, subfolder)
                if url: setattr(c, field, url)
        db.session.add(c); db.session.flush()
        c.subscribers.append(current_user)
        db.session.commit()
        flash(f"Channel '{name}' created!", "success")
        return redirect(url_for("channel_detail", slug=c.slug))
    return render_template("create_channel.html")


@app.route("/channels/<slug>")
@login_required
def channel_detail(slug):
    c     = Channel.query.filter_by(slug=slug).first_or_404()
    is_sub = c.subscribers.filter(User.id == current_user.id).count() > 0
    return render_template("channel_detail.html", channel=c, is_subscribed=is_sub,
                           posts=c.posts.order_by(ChannelPost.created_at.desc()).limit(30).all(),
                           is_own=(c.owner_id == current_user.id))


@app.route("/channels/<slug>/subscribe", methods=["POST"])
@login_required
def subscribe_channel(slug):
    c = Channel.query.filter_by(slug=slug).first_or_404()
    if c.subscribers.filter(User.id == current_user.id).count():
        c.subscribers.remove(current_user); subscribed = False
        flash(f"Unsubscribed from '{c.name}'", "info")
    else:
        c.subscribers.append(current_user); subscribed = True
        flash(f"Subscribed to '{c.name}'", "success")
    db.session.commit()
    return jsonify({"subscribed": subscribed, "count": c.sub_count})


@app.route("/channels/<slug>/publish", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def channel_publish(slug):
    c = Channel.query.filter_by(slug=slug).first_or_404()
    if c.owner_id != current_user.id:
        abort(403)
    content = request.form.get("content", "").strip()
    media_file = request.files.get("media")
    media_url = media_type = ""
    if media_file and media_file.filename:
        ext = media_file.filename.rsplit(".", 1)[-1].lower()
        subfolder = "videos" if ext in ALLOWED_VIDEO else "images"
        media_url  = save_file(media_file, subfolder) or ""
        media_type = "video" if ext in ALLOWED_VIDEO else "image"
    p = ChannelPost(channel_id=c.id, content=content,
                    media_url=media_url, media_type=media_type or "text")
    db.session.add(p)
    for sub in c.subscribers:
        if sub.id != current_user.id:
            db.session.add(Notification(user_id=sub.id, from_user_id=current_user.id,
                                        type="channel_post", text=f"New post in {c.name}"))
    db.session.commit()
    flash("Post published in channel!", "success")
    return redirect(url_for("channel_detail", slug=slug))


# ─── Notifications ────────────────────────────────────────────────────────────

@app.route("/notifications")
@login_required
def notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id)\
                               .order_by(Notification.created_at.desc()).limit(50).all()
    Notification.query.filter_by(user_id=current_user.id, is_read=False)\
                      .update({"is_read": True})
    db.session.commit()
    return render_template("notifications.html", notifs=notifs)


# ─── Debug ───────────────────────────────────────────────────────────────────

@app.route("/debug/uploads")
@login_required
def debug_uploads():
    if not current_user.is_admin:
        abort(403)
    uf = app.config['UPLOAD_FOLDER']
    result = {"upload_folder": uf, "exists": os.path.exists(uf),
              "is_render": is_render, "subfolders": {}}
    if os.path.exists(uf):
        for sf in UPLOAD_SUBFOLDERS:
            path = os.path.join(uf, sf)
            if os.path.exists(path):
                try:
                    files = os.listdir(path)
                    result['subfolders'][sf] = {
                        "exists": True, "writable": os.access(path, os.W_OK),
                        "file_count": len(files), "recent_files": files[-20:],
                    }
                except Exception as e:
                    result['subfolders'][sf] = {"exists": True, "error": str(e)}
            else:
                result['subfolders'][sf] = {"exists": False}
    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════════════
#  SOCKET.IO EVENTS
# ══════════════════════════════════════════════════════════════════════════════

def _emit_notification(user_id, data):
    socketio.emit("new_notification", data, room=f"user_{user_id}")


@socketio.on("connect")
def handle_connect():
    if current_user.is_authenticated:
        join_room(f"user_{current_user.id}")
        logger.debug(f"WS connect: user {current_user.id}")


@socketio.on("disconnect")
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_seen = datetime.utcnow()
        try: db.session.commit()
        except Exception: db.session.rollback()


@socketio.on("join_chat")
def on_join_chat(data):
    room = data.get("room")
    if room: join_room(room); emit("status", {"msg": "joined"}, room=room)


@socketio.on("leave_chat")
def on_leave_chat(data):
    room = data.get("room")
    if room: leave_room(room)


@socketio.on("typing")
def on_typing(data):
    room = data.get("room"); user = data.get("user")
    if room and user:
        emit("typing", {"user": user}, room=room, include_self=False)


@socketio.on("join_group_room")
def on_join_group(data):
    gid = data.get("group_id")
    if gid and current_user.is_authenticated:
        g = Group.query.get(gid)
        if g and g.members.filter(User.id == current_user.id).count():
            join_room(f"group_{gid}")


@socketio.on("leave_group_room")
def on_leave_group(data):
    gid = data.get("group_id")
    if gid: leave_room(f"group_{gid}")


@socketio.on("join_channel_room")
def on_join_channel(data):
    cid = data.get("channel_id")
    if cid and current_user.is_authenticated:
        c = Channel.query.get(cid)
        if c and c.subscribers.filter(User.id == current_user.id).count():
            join_room(f"channel_{cid}")


@socketio.on("leave_channel_room")
def on_leave_channel(data):
    cid = data.get("channel_id")
    if cid: leave_room(f"channel_{cid}")


@socketio.on("join_user_room")
def on_join_user():
    if current_user.is_authenticated:
        join_room(f"user_{current_user.id}")


# WebRTC signaling
@socketio.on("webrtc_offer")
def on_webrtc_offer(data):
    room = data.get("room")
    if room:
        emit("webrtc_offer", {"offer": data.get("offer"), "from": current_user.id},
             room=room, include_self=False)


@socketio.on("webrtc_answer")
def on_webrtc_answer(data):
    room = data.get("room")
    if room:
        emit("webrtc_answer", {"answer": data.get("answer"), "from": current_user.id},
             room=room, include_self=False)


@socketio.on("webrtc_ice_candidate")
def on_webrtc_ice(data):
    room = data.get("room")
    if room:
        emit("webrtc_ice_candidate",
             {"candidate": data.get("candidate"), "from": current_user.id},
             room=room, include_self=False)


# ══════════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg="Bad request."), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, msg="Access forbidden."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, msg="Page not found."), 404

@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413,
                           msg="File too large. Max upload: 100 MB."), 413

@app.errorhandler(429)
def too_many(e):
    return render_template("error.html", code=429,
                           msg="Too many requests — please slow down."), 429

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500: {e}")
    return render_template("error.html", code=500,
                           msg="Internal server error."), 500


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════════════════

def create_admin_user():
    try:
        if not User.query.filter_by(username='admin').first():
            admin_pw = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
            admin    = User(username='admin', email='admin@kildear.com',
                            display_name='Administrator',
                            is_admin=True, is_verified=True)
            admin.set_password(admin_pw)
            db.session.add(admin); db.session.commit()
            logger.info("✅ Admin user created (change the password!)")
    except Exception as e:
        logger.error(f"create_admin_user error: {e}")


def run_migrations():
    try:
        inspector = db.inspect(db.engine)
        columns   = [c['name'] for c in inspector.get_columns('user')]
        tables    = inspector.get_table_names()
        changes   = []

        for col, definition in [
            ('is_admin',            'BOOLEAN DEFAULT FALSE'),
            ('two_factor_enabled',  'BOOLEAN DEFAULT FALSE'),
            ('two_factor_secret',   'VARCHAR(32)'),
            ('is_online',           'BOOLEAN DEFAULT FALSE'),
            ('last_seen',           'DATETIME'),
            ('failed_logins',       'INTEGER DEFAULT 0'),
            ('locked_until',        'DATETIME'),
        ]:
            if col not in columns:
                db.session.execute(text(f'ALTER TABLE "user" ADD COLUMN {col} {definition}'))
                changes.append(col)

        if changes:
            db.session.commit()
            logger.info(f"✅ Migrated columns: {', '.join(changes)}")

        # Ensure new tables exist
        new_tables = {'login_history', 'voice_message', 'call', 'report'} - set(tables)
        if new_tables:
            db.create_all()
            logger.info(f"✅ Created tables: {', '.join(new_tables)}")

        db.session.execute(text('UPDATE "user" SET is_admin = FALSE WHERE is_admin IS NULL'))
        db.session.execute(text('UPDATE "user" SET two_factor_enabled = FALSE WHERE two_factor_enabled IS NULL'))
        db.session.execute(text('UPDATE "user" SET is_online = FALSE WHERE is_online IS NULL'))
        db.session.execute(text('UPDATE "user" SET failed_logins = 0 WHERE failed_logins IS NULL'))
        db.session.commit()

    except Exception as e:
        logger.error(f"Migration error: {e}")
        db.session.rollback()


def init_app():
    with app.app_context():
        try:
            db.create_all()
            run_migrations()
            ensure_upload_folders()
            create_admin_user()
            logger.info("🎉 Kildear initialised successfully")
        except Exception as e:
            logger.error(f"init_app error: {e}")


if __name__ == "__main__":
    init_app()
    port = int(os.environ.get("PORT", 5000))

    print("\n" + "=" * 60)
    print("🚀  KILDEAR — SECURITY-HARDENED")
    print("=" * 60)
    print(f"🌐  Port            : {port}")
    print(f"📁  Uploads         : {app.config['UPLOAD_FOLDER']}")
    print(f"🐍  Python          : {platform.python_version()}")
    print(f"🖥️   Platform        : {platform.system()}")
    print(f"🎯  Mode            : {'PRODUCTION' if is_production else 'DEVELOPMENT'}")
    print("🛡️   Security layers : 7")
    print("=" * 60 + "\n")

    socketio.run(app, debug=not is_production,
                 host="0.0.0.0", port=port,
                 allow_unsafe_werkzeug=not is_production)
