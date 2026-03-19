"""
Kildear Social Network — app.py
Full-featured backend: auth, posts, video, chat, groups, channels,
profile customization, search, and multi-layer security.
"""

import os
import re
import time
import uuid
import html
import logging
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, abort, session, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func, and_

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
#  App Configuration
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Определяем базовую директорию
basedir = os.path.abspath(os.path.dirname(__file__))

# Используем SQLite
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'kildear.db')

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(48).hex()),
    SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500 MB max upload
    UPLOAD_FOLDER=os.path.join("static", "uploads"),
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION", False),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

ALLOWED_IMAGE = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_VIDEO = {"mp4", "webm", "mov", "avi", "mkv"}

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_mgr = LoginManager(app)
login_mgr.login_view = "login"
login_mgr.login_message_category = "info"
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute", "3000 per hour"],
    storage_uri="memory://",
)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ──────────────────────────────────────────────────────────────────────────────
#  Template Filters
# ──────────────────────────────────────────────────────────────────────────────
@app.template_filter('timeago')
def timeago_filter(date):
    """Convert datetime to 'time ago' format"""
    if not date:
        return 'recently'

    now = datetime.utcnow()
    diff = now - date

    if diff.days > 365:
        return f"{diff.days // 365}y ago"
    elif diff.days > 30:
        return f"{diff.days // 30}mo ago"
    elif diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600}h ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60}m ago"
    else:
        return "just now"


@app.template_filter('format_date')
def format_date_filter(date, format='%b %d, %Y'):
    """Format date with custom format"""
    if not date:
        return ''
    return date.strftime(format)


@app.template_filter('format_time')
def format_time_filter(date, format='%H:%M'):
    """Format time with custom format"""
    if not date:
        return ''
    return date.strftime(format)


# ──────────────────────────────────────────────────────────────────────────────
#  DDoS / Abuse Protection
# ──────────────────────────────────────────────────────────────────────────────
_req_log: dict = defaultdict(list)
_blocked_ips: set = set()
_fail_log: dict = defaultdict(list)


@app.before_request
def ddos_shield():
    ip = get_remote_address()
    if ip in _blocked_ips:
        abort(429)
    now = time.time()
    window = [t for t in _req_log[ip] if now - t < 10]
    window.append(now)
    _req_log[ip] = window
    if len(window) > 200:
        _blocked_ips.add(ip)
        app.logger.warning(f"[DDoS] Blocked IP: {ip}")
        abort(429)
    if request.content_length and request.content_length > app.config["MAX_CONTENT_LENGTH"]:
        abort(413)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "camera=(), "
        "microphone=(), "
        "accelerometer=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "payment=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://fonts.googleapis.com "
        "https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "connect-src 'self' wss: ws:;"
    )
    return response


def track_failure(ip: str):
    now = time.time()
    fails = [t for t in _fail_log[ip] if now - t < 300]
    fails.append(now)
    _fail_log[ip] = fails
    if len(fails) >= 20:
        _blocked_ips.add(ip)


# ──────────────────────────────────────────────────────────────────────────────
#  Helper Utilities
# ──────────────────────────────────────────────────────────────────────────────
def allowed_file(filename: str, allowed: set) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def save_file(file, subfolder: str):
    """Сохраняет файл и возвращает URL или None"""
    if not file or not file.filename:
        return None

    try:
        # Получаем расширение
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not ext:
            return None

        # Проверяем разрешенные типы
        if ext not in ALLOWED_IMAGE and ext not in ALLOWED_VIDEO:
            return None

        # Генерируем уникальное имя
        filename = f"{uuid.uuid4().hex}.{ext}"

        # Создаем путь
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(upload_path, exist_ok=True)

        # Полный путь к файлу
        file_path = os.path.join(upload_path, filename)

        # Сохраняем файл
        file.save(file_path)

        # Проверяем, что файл не опасный (простая проверка)
        if ext in ALLOWED_IMAGE:
            # Проверка изображения на валидность
            try:
                from PIL import Image
                img = Image.open(file_path)
                img.verify()
            except:
                os.remove(file_path)
                return None

        logger.info(f"✅ Файл сохранен: {file_path}")
        return f"/static/uploads/{subfolder}/{filename}"

    except Exception as e:
        logger.error(f"❌ Ошибка при сохранении файла: {e}")
        return None


def sanitize(text: str) -> str:
    return html.escape(text.strip()) if text else ""


# ──────────────────────────────────────────────────────────────────────────────
#  Database Models
# ──────────────────────────────────────────────────────────────────────────────

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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(60), default="")
    bio = db.Column(db.String(500), default="")
    avatar = db.Column(db.String(300), default="/static/default_avatar.png")
    cover_photo = db.Column(db.String(300), default="")
    website = db.Column(db.String(200), default="")
    location = db.Column(db.String(100), default="")
    accent_color = db.Column(db.String(7), default="#6c63ff")
    is_private = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # WebRTC signaling
    webrtc_ice_servers = db.Column(db.Text, default='[]')
    webrtc_config = db.Column(db.Text, default='{}')

    posts = db.relationship("Post", backref="author", lazy="dynamic",
                            foreign_keys="Post.user_id")
    sent_msgs = db.relationship("Message", backref="sender", lazy="dynamic",
                                foreign_keys="Message.sender_id")
    recv_msgs = db.relationship("Message", backref="receiver", lazy="dynamic",
                                foreign_keys="Message.receiver_id")
    notifications = db.relationship("Notification", backref="recipient", lazy="dynamic",
                                    foreign_keys="Notification.user_id")
    comments = db.relationship("Comment", backref="author", lazy="dynamic")
    owned_groups = db.relationship("Group", backref="owner", lazy="dynamic")
    owned_channels = db.relationship("Channel", backref="owner", lazy="dynamic")

    blocked_users = db.relationship(
        "User", secondary=blocks,
        primaryjoin=blocks.c.blocker_id == id,
        secondaryjoin=blocks.c.blocked_id == id,
        backref=db.backref("blocked_by", lazy="dynamic"),
        lazy="dynamic"
    )

    following = db.relationship(
        "User", secondary=follows,
        primaryjoin=follows.c.follower_id == id,
        secondaryjoin=follows.c.followed_id == id,
        backref=db.backref("followers", lazy="dynamic"),
        lazy="dynamic"
    )

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

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
    def follower_count(self):
        return self.followers.count()

    @property
    def following_count(self):
        return self.following.count()

    @property
    def post_count(self):
        return self.posts.count()


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, default="")
    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    thumbnail = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)

    liked_by = db.relationship("User", secondary=post_likes, backref="liked_posts", lazy="dynamic")
    comments = db.relationship("Comment", backref="post", lazy="dynamic", cascade="all,delete")

    @property
    def like_count(self):
        return self.liked_by.count()

    @property
    def comment_count(self):
        return self.comments.count()

    def is_liked_by(self, user) -> bool:
        return self.liked_by.filter(post_likes.c.user_id == user.id).count() > 0


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, default="")
    media_url = db.Column(db.String(300), default="")
    is_read = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    replies = db.relationship("Message", backref=db.backref("reply_to", remote_side=[id]))


class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    callee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    call_type = db.Column(db.String(10), nullable=False)  # 'audio' or 'video'
    status = db.Column(db.String(20), default='missed')  # 'missed', 'completed', 'rejected'
    duration = db.Column(db.Integer, default=0)  # in seconds
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)

    caller = db.relationship("User", foreign_keys=[caller_id])
    callee = db.relationship("User", foreign_keys=[callee_id])


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar = db.Column(db.String(300), default="/static/default_group.png")
    cover = db.Column(db.String(300), default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship("User", secondary=group_members,
                              backref="groups", lazy="dynamic")
    posts = db.relationship("GroupPost", backref="group", lazy="dynamic",
                            cascade="all,delete")

    @property
    def member_count(self):
        return self.members.count()


class GroupPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, default="")
    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship("User")


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar = db.Column(db.String(300), default="/static/default_channel.png")
    cover = db.Column(db.String(300), default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_nsfw = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    subscribers = db.relationship("User", secondary=channel_subs,
                                  backref="subscribed_channels", lazy="dynamic")
    posts = db.relationship("ChannelPost", backref="channel", lazy="dynamic",
                            cascade="all,delete")

    @property
    def sub_count(self):
        return self.subscribers.count()


class ChannelPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey("channel.id"), nullable=False)
    content = db.Column(db.Text, default="")
    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    type = db.Column(db.String(30), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    call_id = db.Column(db.Integer, db.ForeignKey("call.id"), nullable=True)
    text = db.Column(db.String(300), default="")
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    from_user = db.relationship("User", foreign_keys=[from_user_id])
    call = db.relationship("Call", foreign_keys=[call_id])


# ──────────────────────────────────────────────────────────────────────────────
#  Helper Functions for Templates
# ──────────────────────────────────────────────────────────────────────────────
def notification_link(notif):
    """Generate link for notification based on type"""
    if notif.type == 'like' or notif.type == 'comment':
        if notif.post_id:
            return url_for('view_post', post_id=notif.post_id)
    elif notif.type == 'follow':
        if notif.from_user:
            return url_for('profile', username=notif.from_user.username)
    elif notif.type == 'mention':
        if notif.post_id:
            return url_for('view_post', post_id=notif.post_id)
    elif notif.type in ['missed_call', 'incoming_call']:
        if notif.call_id:
            return url_for('chat', username=notif.from_user.username)
    return '#'


def notification_icon(notif):
    """Get icon for notification type"""
    icons = {
        'like': '❤️',
        'comment': '💬',
        'follow': '👤',
        'mention': '@',
        'group_invite': '👥',
        'channel_post': '📢',
        'missed_call': '📞',
        'incoming_call': '📞'
    }
    return icons.get(notif.type, '🔔')


def notification_text(notif):
    """Get text for notification"""
    if notif.text:
        return notif.text

    if notif.type == 'like':
        return f"{notif.from_user.username} liked your post"
    elif notif.type == 'comment':
        return f"{notif.from_user.username} commented on your post"
    elif notif.type == 'follow':
        return f"{notif.from_user.username} started following you"
    elif notif.type == 'mention':
        return f"{notif.from_user.username} mentioned you in a post"
    elif notif.type == 'missed_call':
        return f"Missed {notif.call.call_type} call from {notif.from_user.username}"
    elif notif.type == 'incoming_call':
        return f"Incoming {notif.call.call_type} call from {notif.from_user.username}"
    return "New notification"


# ──────────────────────────────────────────────────────────────────────────────
#  Auth loader
# ──────────────────────────────────────────────────────────────────────────────
@login_mgr.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ──────────────────────────────────────────────────────────────────────────────
#  Context Processors
# ──────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    unread = 0
    notif_count = 0
    if current_user.is_authenticated:
        unread = Message.query.filter_by(
            receiver_id=current_user.id, is_read=False, is_deleted=False).count()
        notif_count = Notification.query.filter_by(
            user_id=current_user.id, is_read=False).count()

    return dict(
        unread_messages=unread,
        notif_count=notif_count,
        csrf_token=generate_csrf,
        notification_link=notification_link,
        notification_icon=notification_icon,
        notification_text=notification_text,
        now=datetime.utcnow()
    )


# ──────────────────────────────────────────────────────────────────────────────
#  API Routes for Notifications
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/unread_counts")
@login_required
def unread_counts():
    notif_count = Notification.query.filter_by(
        user_id=current_user.id, is_read=False).count()
    msg_count = Message.query.filter_by(
        receiver_id=current_user.id, is_read=False, is_deleted=False).count()
    return jsonify({"notifications": notif_count, "messages": msg_count})


@app.route("/api/mark_notification_read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    """Mark a single notification as read"""
    notif = Notification.query.filter_by(id=notif_id, user_id=current_user.id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Notification not found"}), 404


@app.route("/api/mark_all_notifications_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"success": True})


# ──────────────────────────────────────────────────────────────────────────────
#  Auth Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

            if not username or not email or not password:
                flash("Все поля обязательны для заполнения", "error")
                return render_template("register.html")

            if not re.match(r"^[a-zA-Z0-9_]{3,40}$", username):
                flash("Имя пользователя должно быть 3-40 символов и содержать только буквы, цифры и подчеркивания",
                      "error")
                return render_template("register.html")

            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                flash("Неверный формат email", "error")
                return render_template("register.html")

            if len(password) < 6:
                flash("Пароль должен быть не менее 6 символов", "error")
                return render_template("register.html")

            if password != confirm:
                flash("Пароли не совпадают", "error")
                return render_template("register.html")

            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()

            if existing_user:
                if existing_user.username == username:
                    flash("Пользователь с таким именем уже существует", "error")
                else:
                    flash("Пользователь с таким email уже существует", "error")
                return render_template("register.html")

            user = User(
                username=username,
                email=email,
                display_name=username,
                avatar="/static/default_avatar.png",
                bio="",
                accent_color="#6c63ff",
                is_private=False,
                is_verified=False,
                is_banned=False,
                webrtc_ice_servers='[]',
                webrtc_config='{}'
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            login_user(user, remember=True)
            flash(f"Добро пожаловать в Kildear, {username}! 🎉", "success")
            return redirect(url_for("index"))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка при регистрации: {str(e)}")
            flash("Произошла ошибка при регистрации. Пожалуйста, попробуйте позже.", "error")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        ip = get_remote_address()

        user = User.query.filter(
            or_(func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower())).first()

        if not user or not user.check_password(password):
            track_failure(ip)
            flash("Неверные учетные данные.", "error")
            return render_template("login.html")

        if user.is_banned:
            flash("Этот аккаунт заблокирован.", "error")
            return render_template("login.html")

        login_user(user, remember=remember)
        session.permanent = remember

        # Update online status
        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.session.commit()

        next_page = request.args.get("next")
        flash(f"С возвращением, {user.username}! 👋", "success")
        return redirect(next_page or url_for("index"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()

    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


# ──────────────────────────────────────────────────────────────────────────────
#  Feed / Home
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    followed_ids = [u.id for u in current_user.following.all()] + [current_user.id]
    posts = (Post.query
             .filter(Post.user_id.in_(followed_ids))
             .filter(Post.user_id.notin_([b.id for b in current_user.blocked_users]))
             .order_by(Post.created_at.desc())
             .paginate(page=page, per_page=15, error_out=False))
    suggestions = (User.query
                   .filter(User.id.notin_(followed_ids))
                   .filter(User.id != current_user.id)
                   .filter(User.id.notin_([b.id for b in current_user.blocked_users]))
                   .order_by(func.random()).limit(5).all())
    return render_template("index.html", posts=posts, suggestions=suggestions)


# ──────────────────────────────────────────────────────────────────────────────
#  Posts
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/post/create", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_post():
    content = request.form.get("content", "").strip()
    media_file = request.files.get("media")
    media_url = ""
    media_type = "text"

    if media_file and media_file.filename:
        try:
            ext = media_file.filename.rsplit(".", 1)[-1].lower() if '.' in media_file.filename else ''
            logger.info(f"Загружается файл: {media_file.filename}, расширение: {ext}")

            if ext in ALLOWED_VIDEO:
                media_url = save_file(media_file, "videos")
                media_type = "video"
                logger.info(f"Видео сохранено: {media_url}")
            elif ext in ALLOWED_IMAGE:
                media_url = save_file(media_file, "images")
                media_type = "image"
                logger.info(f"Изображение сохранено: {media_url}")
            else:
                flash(f"Неподдерживаемый тип файла. Разрешены: изображения {ALLOWED_IMAGE} и видео {ALLOWED_VIDEO}",
                      "error")
                return redirect(url_for("index"))
        except Exception as e:
            logger.error(f"Ошибка при сохранении файла: {e}")
            flash("Ошибка при загрузке файла", "error")
            return redirect(url_for("index"))

    if not content and not media_url:
        flash("Пост не может быть пустым.", "error")
        return redirect(url_for("index"))

    post = Post(
        user_id=current_user.id,
        content=content,
        media_url=media_url or "",
        media_type=media_type
    )

    db.session.add(post)
    db.session.commit()

    flash("Пост опубликован!", "success")
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>")
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Check if user is blocked
    if post.author.id in [b.id for b in current_user.blocked_users]:
        abort(403)

    post.views += 1
    db.session.commit()
    comments = post.comments.order_by(Comment.created_at.asc()).all()
    return render_template("post_detail.html", post=post, comments=comments)


@app.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Check if user is blocked
    if post.author.id in [b.id for b in current_user.blocked_users]:
        return jsonify({"error": "Cannot interact with blocked user"}), 403

    if post.is_liked_by(current_user):
        post.liked_by.remove(current_user)
        liked = False
    else:
        post.liked_by.append(current_user)
        liked = True
        if post.user_id != current_user.id:
            n = Notification(
                user_id=post.user_id,
                from_user_id=current_user.id,
                type="like",
                post_id=post.id,
                text=f"{current_user.username} liked your post."
            )
            db.session.add(n)
    db.session.commit()
    return jsonify({"liked": liked, "count": post.like_count})


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)

    # Check if user is blocked
    if post.author.id in [b.id for b in current_user.blocked_users]:
        return jsonify({"error": "Cannot interact with blocked user"}), 403

    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"error": "Comment cannot be empty."}), 400
    c = Comment(post_id=post.id, user_id=current_user.id, content=content)
    db.session.add(c)
    if post.user_id != current_user.id:
        n = Notification(
            user_id=post.user_id,
            from_user_id=current_user.id,
            type="comment",
            post_id=post.id,
            text=f"{current_user.username} commented on your post."
        )
        db.session.add(n)
    db.session.commit()
    return jsonify({
        "id": c.id,
        "username": current_user.username,
        "avatar": current_user.avatar,
        "content": c.content,
        "created_at": c.created_at.strftime("%b %d, %Y"),
    })


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


# ──────────────────────────────────────────────────────────────────────────────
#  Profile
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/u/<username>")
@login_required
def profile(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    # Check if user is blocked
    if user.id in [b.id for b in current_user.blocked_users]:
        flash("You have blocked this user", "info")

    page = request.args.get("page", 1, type=int)
    tab = request.args.get("tab", "posts")

    # Filter posts if blocked
    if user.id in [b.id for b in current_user.blocked_users]:
        posts = []
        videos = []
    else:
        posts = (user.posts.order_by(Post.created_at.desc())
                 .paginate(page=page, per_page=12, error_out=False))
        videos = (user.posts.filter_by(media_type="video")
                  .order_by(Post.created_at.desc()).limit(12).all())

    is_own = user.id == current_user.id
    is_following = current_user.is_following(user) if not is_own else False
    is_blocked = current_user.is_blocked(user) if not is_own else False

    return render_template("profile.html", user=user, posts=posts,
                           videos=videos, is_own=is_own,
                           is_following=is_following, is_blocked=is_blocked,
                           tab=tab)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        current_user.display_name = request.form.get("display_name", "")[:60]
        current_user.bio = request.form.get("bio", "")[:500]
        current_user.website = request.form.get("website", "")[:200]
        current_user.location = request.form.get("location", "")[:100]
        current_user.accent_color = request.form.get("accent_color", "#6c63ff")[:7]
        current_user.is_private = bool(request.form.get("is_private"))

        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            url = save_file(avatar, "avatars")
            if url:
                current_user.avatar = url

        cover = request.files.get("cover_photo")
        if cover and cover.filename:
            url = save_file(cover, "covers")
            if url:
                current_user.cover_photo = url

        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for("profile", username=current_user.username))
    return render_template("edit_profile.html")


@app.route("/follow/<username>", methods=["POST"])
@login_required
def follow(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()
    if user.id == current_user.id:
        return jsonify({"error": "Cannot follow yourself."}), 400

    # Check if user is blocked
    if user.id in [b.id for b in current_user.blocked_users]:
        return jsonify({"error": "Cannot follow blocked user"}), 400

    if current_user.is_following(user):
        current_user.following.remove(user)
        following = False
    else:
        current_user.following.append(user)
        following = True
        n = Notification(
            user_id=user.id,
            from_user_id=current_user.id,
            type="follow",
            text=f"{current_user.username} started following you."
        )
        db.session.add(n)
    db.session.commit()
    return jsonify({"following": following, "followers": user.follower_count})


# ──────────────────────────────────────────────────────────────────────────────
#  Block/Unblock Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/user/<int:user_id>/block", methods=["POST"])
@login_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({"error": "Cannot block yourself"}), 400

    if current_user.block(user):
        db.session.commit()

        # Remove from following/followers
        if current_user.is_following(user):
            current_user.following.remove(user)
        if user.is_following(current_user):
            user.following.remove(current_user)

        db.session.commit()
        return jsonify({"success": True, "blocked": True})
    return jsonify({"error": "User already blocked"}), 400


@app.route("/user/<int:user_id>/unblock", methods=["POST"])
@login_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.unblock(user):
        db.session.commit()
        return jsonify({"success": True, "blocked": False})
    return jsonify({"error": "User not blocked"}), 400


# ──────────────────────────────────────────────────────────────────────────────
#  Video Feed
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/video")
@login_required
def video_feed():
    page = request.args.get("page", 1, type=int)
    videos = (Post.query.filter_by(media_type="video")
              .filter(Post.user_id.notin_([b.id for b in current_user.blocked_users]))
              .order_by(Post.created_at.desc())
              .paginate(page=page, per_page=10, error_out=False))
    return render_template("video.html", videos=videos)


# ──────────────────────────────────────────────────────────────────────────────
#  Search
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/search")
@login_required
@limiter.limit("60 per minute")
def search():
    q = request.args.get("q", "").strip()
    tab = request.args.get("tab", "people")

    # Remove @ symbol if present
    if q.startswith('@'):
        q = q[1:]

    users = []
    posts = []
    groups = []
    channels = []

    if q:
        pattern = f"%{q}%"
        # Search users by username or display_name (exclude blocked)
        users = User.query.filter(
            or_(
                User.username.ilike(pattern),
                User.display_name.ilike(pattern)
            )
        ).filter(User.id != current_user.id) \
            .filter(User.id.notin_([b.id for b in current_user.blocked_users])) \
            .limit(20).all()

        posts = Post.query.filter(Post.content.ilike(pattern)) \
            .filter(Post.user_id.notin_([b.id for b in current_user.blocked_users])) \
            .limit(20).all()
        groups = Group.query.filter(
            or_(Group.name.ilike(pattern),
                Group.description.ilike(pattern))).limit(10).all()
        channels = Channel.query.filter(
            or_(Channel.name.ilike(pattern),
                Channel.description.ilike(pattern))).limit(10).all()

    # For AJAX requests from chat
    if request.args.get("ajax") == "1" or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "users": [{
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
                "avatar": u.avatar or "/static/default_avatar.png",
                "is_online": u.is_online
            } for u in users]
        })

    return render_template("search.html", q=q, tab=tab,
                           users=users, posts=posts,
                           groups=groups, channels=channels)


# ──────────────────────────────────────────────────────────────────────────────
#  Chat
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/chat")
@login_required
def chat_list():
    """Show all unique conversation partners."""
    try:
        # Получаем всех пользователей, с которыми был обмен сообщениями
        sent_to = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set = {r[0] for r in sent_to} | {r[0] for r in recv_from}

        # Исключаем заблокированных пользователей (если есть колонка)
        blocked_ids = []
        if hasattr(current_user, 'blocked_users'):
            blocked_ids = [b.id for b in current_user.blocked_users]
            uid_set = uid_set - set(blocked_ids)

        partners = User.query.filter(User.id.in_(uid_set)).all()

        conversations = []
        for p in partners:
            # Получаем последнее сообщение
            last_msg_query = Message.query.filter(
                or_(
                    and_(Message.sender_id == current_user.id, Message.receiver_id == p.id),
                    and_(Message.sender_id == p.id, Message.receiver_id == current_user.id)
                )
            )

            # Добавляем фильтр is_deleted если есть колонка
            if hasattr(Message, 'is_deleted'):
                last_msg_query = last_msg_query.filter(Message.is_deleted == False)

            last_msg = last_msg_query.order_by(Message.created_at.desc()).first()

            # Считаем непрочитанные
            unread_query = Message.query.filter_by(
                sender_id=p.id,
                receiver_id=current_user.id,
                is_read=False
            )

            if hasattr(Message, 'is_deleted'):
                unread_query = unread_query.filter(Message.is_deleted == False)

            unread = unread_query.count()

            conversations.append({
                "user": p,
                "last": last_msg,
                "unread": unread
            })

        # Сортируем по времени последнего сообщения
        conversations.sort(
            key=lambda x: x["last"].created_at if x["last"] else datetime.min,
            reverse=True
        )

        return render_template("chat_list.html", conversations=conversations)

    except Exception as e:
        logger.error(f"Ошибка в chat_list: {e}")
        flash(f"Ошибка при загрузке чата: {str(e)}", "error")
        return redirect(url_for("index"))

@app.route("/chat/<username>")
@login_required
def chat(username):
    try:
        partner = User.query.filter(
            func.lower(User.username) == username.lower()).first_or_404()

        # Check if user is blocked
        is_blocked = current_user.is_blocked(partner)

        # Mark messages as read (only if not blocked)
        if not is_blocked:
            Message.query.filter_by(
                sender_id=partner.id, receiver_id=current_user.id, is_read=False
            ).update({"is_read": True})
            db.session.commit()

        # Get messages (exclude if blocked)
        if is_blocked:
            messages = []
        else:
            messages = (Message.query
                        .filter(or_(
                and_(Message.sender_id == current_user.id, Message.receiver_id == partner.id),
                and_(Message.sender_id == partner.id, Message.receiver_id == current_user.id)
            ))
                        .filter(Message.is_deleted == False)
                        .order_by(Message.created_at.asc()).limit(100).all())

        # Get all conversations for sidebar
        sent_to = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set = {r[0] for r in sent_to} | {r[0] for r in recv_from}

        # Exclude blocked users
        blocked_ids = [b.id for b in current_user.blocked_users]
        uid_set = uid_set - set(blocked_ids)

        partners_list = User.query.filter(User.id.in_(uid_set)).all()

        conversations = []
        for p in partners_list:
            last = (Message.query
                    .filter(or_(
                and_(Message.sender_id == current_user.id, Message.receiver_id == p.id),
                and_(Message.sender_id == p.id, Message.receiver_id == current_user.id)
            ))
                    .filter(Message.is_deleted == False)
                    .order_by(Message.created_at.desc()).first())
            unread = (Message.query
                      .filter_by(sender_id=p.id, receiver_id=current_user.id, is_read=False, is_deleted=False)
                      .count())
            conversations.append({
                "user": p,
                "last": last,
                "unread": unread
            })

        conversations.sort(key=lambda x: x["last"].created_at if x["last"] else datetime.min, reverse=True)

        return render_template("chat.html",
                               partner=partner,
                               messages=messages,
                               conversations=conversations,
                               is_blocked=is_blocked)

    except Exception as e:
        logger.error(f"Ошибка в chat: {e}")
        flash("Ошибка при загрузке чата", "error")
        return redirect(url_for("chat_list"))


@app.route("/chat/<username>/send", methods=["POST"])
@login_required
@limiter.limit("120 per minute")
def send_message(username):
    try:
        partner = User.query.filter(
            func.lower(User.username) == username.lower()).first_or_404()

        # Check if user is blocked
        if current_user.is_blocked(partner):
            return jsonify({"error": "Cannot send message to blocked user"}), 403

        content = request.form.get("content", "").strip()
        media_file = request.files.get("media")
        media_url = ""
        reply_to_id = request.form.get("reply_to", type=int)

        if media_file and media_file.filename:
            media_url = save_file(media_file, "chat_images") or ""

        if not content and not media_url:
            return jsonify({"error": "Message cannot be empty."}), 400

        msg = Message(
            sender_id=current_user.id,
            receiver_id=partner.id,
            content=content,
            media_url=media_url,
            reply_to_id=reply_to_id
        )
        db.session.add(msg)
        db.session.commit()

        # Create notification for the receiver
        notif = Notification(
            user_id=partner.id,
            from_user_id=current_user.id,
            type="message",
            text=f"{current_user.username} sent you a message"
        )
        db.session.add(notif)
        db.session.commit()

        # Get socket.io room
        room = "_".join(sorted([str(current_user.id), str(partner.id)]))

        # Emit via socket.io
        socketio.emit("new_message", {
            "id": msg.id,
            "sender_id": current_user.id,
            "sender_username": current_user.username,
            "sender_avatar": current_user.avatar,
            "content": msg.content,
            "media_url": msg.media_url,
            "reply_to_id": msg.reply_to_id,
            "created_at": msg.created_at.strftime("%H:%M"),
        }, room=room)

        return jsonify({"ok": True, "id": msg.id})

    except Exception as e:
        logger.error(f"Ошибка в send_message: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/chat/message/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id):
    """Delete a message (soft delete)"""
    try:
        msg = Message.query.get_or_404(message_id)

        # Only allow deleting own messages
        if msg.sender_id != current_user.id:
            return jsonify({"error": "Cannot delete other's messages"}), 403

        msg.is_deleted = True
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Ошибка при удалении сообщения: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/chat/message/<int:message_id>/forward", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def forward_message(message_id):
    """Forward a message to another user"""
    try:
        data = request.get_json()
        to_user_id = data.get('to_user_id')

        original_msg = Message.query.get_or_404(message_id)

        # Check if user can forward this message
        if original_msg.sender_id != current_user.id and original_msg.receiver_id != current_user.id:
            return jsonify({"error": "Cannot forward this message"}), 403

        target_user = User.query.get_or_404(to_user_id)

        # Check if target user is blocked
        if current_user.is_blocked(target_user):
            return jsonify({"error": "Cannot forward to blocked user"}), 403

        # Create forwarded message
        forward_text = f"[Forwarded] {original_msg.content}" if original_msg.content else "[Forwarded Media]"

        new_msg = Message(
            sender_id=current_user.id,
            receiver_id=target_user.id,
            content=forward_text,
            media_url=original_msg.media_url
        )
        db.session.add(new_msg)
        db.session.commit()

        return jsonify({"success": True, "message_id": new_msg.id})

    except Exception as e:
        logger.error(f"Ошибка при пересылке сообщения: {e}")
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────────────────────
#  Call Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/call/start", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def start_call():
    """Start a call with another user"""
    try:
        data = request.get_json()
        callee_id = data.get('callee_id')
        call_type = data.get('type', 'audio')  # 'audio' or 'video'

        callee = User.query.get_or_404(callee_id)

        # Check if user is blocked
        if current_user.is_blocked(callee):
            return jsonify({"error": "Cannot call blocked user"}), 403

        # Create call record
        call = Call(
            caller_id=current_user.id,
            callee_id=callee.id,
            call_type=call_type,
            status='initiated'
        )
        db.session.add(call)
        db.session.commit()

        # Create notification
        notif = Notification(
            user_id=callee.id,
            from_user_id=current_user.id,
            type='incoming_call',
            call_id=call.id,
            text=f"Incoming {call_type} call from {current_user.username}"
        )
        db.session.add(notif)
        db.session.commit()

        # Get WebRTC configuration
        webrtc_config = {
            'iceServers': [
                {'urls': 'stun:stun.l.google.com:19302'},
                {'urls': 'stun:stun1.l.google.com:19302'}
            ]
        }

        # Emit call event via socket.io
        room = "_".join(sorted([str(current_user.id), str(callee.id)]))
        socketio.emit("incoming_call", {
            "call_id": call.id,
            "caller_id": current_user.id,
            "caller_username": current_user.username,
            "caller_avatar": current_user.avatar,
            "type": call_type,
            "webrtc_config": webrtc_config
        }, room=room)

        return jsonify({
            "success": True,
            "call_id": call.id,
            "webrtc_config": webrtc_config
        })

    except Exception as e:
        logger.error(f"Ошибка при начале звонка: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/call/<int:call_id>/accept", methods=["POST"])
@login_required
def accept_call(call_id):
    """Accept an incoming call"""
    try:
        call = Call.query.get_or_404(call_id)

        # Verify this user is the callee
        if call.callee_id != current_user.id:
            return jsonify({"error": "Not authorized"}), 403

        call.status = 'active'
        call.started_at = datetime.utcnow()
        db.session.commit()

        # Emit acceptance via socket.io
        room = "_".join(sorted([str(call.caller_id), str(call.callee_id)]))
        socketio.emit("call_accepted", {
            "call_id": call.id,
            "accepted_by": current_user.id
        }, room=room)

        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Ошибка при принятии звонка: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/call/<int:call_id>/reject", methods=["POST"])
@login_required
def reject_call(call_id):
    """Reject an incoming call"""
    try:
        call = Call.query.get_or_404(call_id)

        # Verify this user is the callee
        if call.callee_id != current_user.id:
            return jsonify({"error": "Not authorized"}), 403

        call.status = 'rejected'
        call.ended_at = datetime.utcnow()
        db.session.commit()

        # Emit rejection via socket.io
        room = "_".join(sorted([str(call.caller_id), str(call.callee_id)]))
        socketio.emit("call_rejected", {
            "call_id": call.id,
            "rejected_by": current_user.id
        }, room=room)

        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Ошибка при отклонении звонка: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/call/<int:call_id>/end", methods=["POST"])
@login_required
def end_call(call_id):
    """End an active call"""
    try:
        call = Call.query.get_or_404(call_id)

        # Verify user is part of the call
        if call.caller_id != current_user.id and call.callee_id != current_user.id:
            return jsonify({"error": "Not authorized"}), 403

        call.status = 'completed'
        call.ended_at = datetime.utcnow()

        # Calculate duration
        if call.started_at:
            duration = (call.ended_at - call.started_at).seconds
            call.duration = duration

        db.session.commit()

        # Create missed call notification for the other party if needed
        other_id = call.caller_id if call.callee_id == current_user.id else call.callee_id
        if call.status == 'missed':
            notif = Notification(
                user_id=other_id,
                from_user_id=current_user.id,
                type='missed_call',
                call_id=call.id,
                text=f"Missed {call.call_type} call from {current_user.username}"
            )
            db.session.add(notif)
            db.session.commit()

        # Emit end call event via socket.io
        room = "_".join(sorted([str(call.caller_id), str(call.callee_id)]))
        socketio.emit("call_ended", {
            "call_id": call.id,
            "ended_by": current_user.id,
            "duration": call.duration
        }, room=room)

        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Ошибка при завершении звонка: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/call/history")
@login_required
def call_history():
    """Get user's call history"""
    try:
        calls = Call.query.filter(
            or_(
                Call.caller_id == current_user.id,
                Call.callee_id == current_user.id
            )
        ).order_by(Call.started_at.desc()).limit(50).all()

        call_list = []
        for call in calls:
            other_user = User.query.get(call.caller_id if call.callee_id == current_user.id else call.callee_id)
            call_list.append({
                "id": call.id,
                "other_user": {
                    "id": other_user.id,
                    "username": other_user.username,
                    "display_name": other_user.display_name,
                    "avatar": other_user.avatar
                },
                "type": call.call_type,
                "status": call.status,
                "duration": call.duration,
                "started_at": call.started_at.isoformat() if call.started_at else None,
                "is_outgoing": call.caller_id == current_user.id
            })

        return jsonify({"calls": call_list})

    except Exception as e:
        logger.error(f"Ошибка при получении истории звонков: {e}")
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────────────────────────────────────
#  Groups
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/groups")
@login_required
def groups():
    my_groups = current_user.groups
    explore = (Group.query.filter(~Group.members.any(User.id == current_user.id))
               .order_by(Group.created_at.desc()).limit(20).all())
    return render_template("groups.html", my_groups=my_groups, explore=explore)


@app.route("/groups/create", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour")
def create_group():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        desc = request.form.get("description", "").strip()[:500]
        priv = bool(request.form.get("is_private"))

        # Создаем slug из названия
        base_slug = re.sub(r"[^a-z0-9-]", "", name.lower().replace(" ", "-"))
        slug = base_slug[:50] + f"-{uuid.uuid4().hex[:6]}"

        g = Group(
            name=name,
            slug=slug,
            description=desc,
            owner_id=current_user.id,
            is_private=priv
        )

        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            url = save_file(avatar, "groups")
            if url:
                g.avatar = url

        db.session.add(g)
        db.session.flush()
        g.members.append(current_user)
        db.session.commit()

        flash(f"Группа '{name}' создана!", "success")
        return redirect(url_for("group_detail", slug=g.slug))

    return render_template("create_group.html")


@app.route("/groups/<slug>")
@login_required
def group_detail(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()
    is_member = g.members.filter(User.id == current_user.id).count() > 0
    posts = g.posts.order_by(GroupPost.created_at.desc()).limit(30).all()

    return render_template(
        "group_detail.html",
        group=g,
        is_member=is_member,
        posts=posts
    )


@app.route("/groups/<slug>/join", methods=["POST"])
@login_required
def join_group(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()

    if not g.members.filter(User.id == current_user.id).count():
        g.members.append(current_user)
        db.session.commit()
        flash(f"Вы присоединились к группе '{g.name}'", "success")
    else:
        flash("Вы уже участник этой группы", "info")

    return redirect(url_for("group_detail", slug=slug))


@app.route("/groups/<slug>/leave", methods=["POST"])
@login_required
def leave_group(slug):
    g = Group.query.filter_by(slug=slug).first_or_404()

    if g.owner_id == current_user.id:
        flash("Владелец не может покинуть группу", "error")
    elif g.members.filter(User.id == current_user.id).count():
        g.members.remove(current_user)
        db.session.commit()
        flash(f"Вы покинули группу '{g.name}'", "info")

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
    media_url = ""
    media_type = "text"

    if media_file and media_file.filename:
        ext = media_file.filename.rsplit(".", 1)[-1].lower()
        if ext in ALLOWED_VIDEO:
            media_url = save_file(media_file, "videos")
            media_type = "video"
        else:
            media_url = save_file(media_file, "images")
            media_type = "image"

    p = GroupPost(
        group_id=g.id,
        user_id=current_user.id,
        content=content,
        media_url=media_url or "",
        media_type=media_type
    )

    db.session.add(p)
    db.session.commit()

    flash("Пост опубликован в группе!", "success")
    return redirect(url_for("group_detail", slug=slug))


# ──────────────────────────────────────────────────────────────────────────────
#  Channels
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/channels")
@login_required
def channels():
    my_channels = current_user.subscribed_channels
    explore = (Channel.query
               .filter(~Channel.subscribers.any(User.id == current_user.id))
               .order_by(Channel.created_at.desc()).limit(20).all())
    return render_template("channels.html", my_channels=my_channels, explore=explore)


@app.route("/channels/create", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour")
def create_channel():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        desc = request.form.get("description", "").strip()[:500]

        # Создаем slug из названия
        base_slug = re.sub(r"[^a-z0-9-]", "", name.lower().replace(" ", "-"))
        slug = base_slug[:50] + f"-{uuid.uuid4().hex[:6]}"

        c = Channel(
            name=name,
            slug=slug,
            description=desc,
            owner_id=current_user.id
        )

        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            url = save_file(avatar, "channels")
            if url:
                c.avatar = url

        db.session.add(c)
        db.session.flush()
        c.subscribers.append(current_user)
        db.session.commit()

        flash(f"Канал '{name}' создан!", "success")
        return redirect(url_for("channel_detail", slug=c.slug))

    return render_template("create_channel.html")


@app.route("/channels/<slug>")
@login_required
def channel_detail(slug):
    c = Channel.query.filter_by(slug=slug).first_or_404()
    is_sub = c.subscribers.filter(User.id == current_user.id).count() > 0
    posts = c.posts.order_by(ChannelPost.created_at.desc()).limit(30).all()
    is_own = c.owner_id == current_user.id

    return render_template(
        "channel_detail.html",
        channel=c,
        is_subscribed=is_sub,
        posts=posts,
        is_own=is_own
    )


@app.route("/channels/<slug>/subscribe", methods=["POST"])
@login_required
def subscribe_channel(slug):
    c = Channel.query.filter_by(slug=slug).first_or_404()

    if c.subscribers.filter(User.id == current_user.id).count():
        c.subscribers.remove(current_user)
        subscribed = False
        flash(f"Вы отписались от канала '{c.name}'", "info")
    else:
        c.subscribers.append(current_user)
        subscribed = True
        flash(f"Вы подписались на канал '{c.name}'", "success")

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
    media_url = ""
    media_type = "text"

    if media_file and media_file.filename:
        ext = media_file.filename.rsplit(".", 1)[-1].lower()
        if ext in ALLOWED_VIDEO:
            media_url = save_file(media_file, "videos")
            media_type = "video"
        else:
            media_url = save_file(media_file, "images")
            media_type = "image"

    p = ChannelPost(
        channel_id=c.id,
        content=content,
        media_url=media_url or "",
        media_type=media_type
    )

    db.session.add(p)
    db.session.commit()

    flash("Пост опубликован в канале!", "success")
    return redirect(url_for("channel_detail", slug=slug))


# ──────────────────────────────────────────────────────────────────────────────
#  Notifications
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/notifications")
@login_required
def notifications():
    notifs = (Notification.query
              .filter_by(user_id=current_user.id)
              .order_by(Notification.created_at.desc()).limit(50).all())

    Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).update({"is_read": True})
    db.session.commit()

    return render_template("notifications.html", notifs=notifs)


# ──────────────────────────────────────────────────────────────────────────────
#  Socket.IO Events
# ──────────────────────────────────────────────────────────────────────────────
@socketio.on("join_chat")
def on_join(data):
    room = data.get("room")
    if room:
        join_room(room)
        emit("status", {"msg": "joined"}, room=room)


@socketio.on("leave_chat")
def on_leave(data):
    room = data.get("room")
    if room:
        leave_room(room)


@socketio.on("typing")
def on_typing(data):
    room = data.get("room")
    user = data.get("user")
    if room and user:
        emit("typing", {"user": user}, room=room, include_self=False)


# WebRTC Signaling for calls
@socketio.on("webrtc_offer")
def on_webrtc_offer(data):
    room = data.get("room")
    if room:
        emit("webrtc_offer", {
            "offer": data.get("offer"),
            "from": current_user.id
        }, room=room, include_self=False)


@socketio.on("webrtc_answer")
def on_webrtc_answer(data):
    room = data.get("room")
    if room:
        emit("webrtc_answer", {
            "answer": data.get("answer"),
            "from": current_user.id
        }, room=room, include_self=False)


@socketio.on("webrtc_ice_candidate")
def on_webrtc_ice_candidate(data):
    room = data.get("room")
    if room:
        emit("webrtc_ice_candidate", {
            "candidate": data.get("candidate"),
            "from": current_user.id
        }, room=room, include_self=False)


# ──────────────────────────────────────────────────────────────────────────────
#  Error Handlers
# ──────────────────────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, msg="Access forbidden."), 403


@app.errorhandler(429)
def too_many(e):
    return render_template("error.html", code=429,
                           msg="Too many requests. Please slow down."), 429


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413,
                           msg="File too large. Maximum upload size is 500 MB."), 413


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template("error.html", code=500,
                           msg="Internal server error."), 500


# ──────────────────────────────────────────────────────────────────────────────
#  Static / Uploads
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ──────────────────────────────────────────────────────────────────────────────
#  DB Init & Run
# ──────────────────────────────────────────────────────────────────────────────
def init_app():
    """Инициализация приложения и создание необходимых файлов и папок."""
    with app.app_context():
        try:
            # Создаем папку instance если её нет
            os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)

            # Создаем таблицы
            db.create_all()
            print("✅ Таблицы созданы успешно")

            # Создаем папки для загрузок
            folders = ['avatars', 'images', 'videos', 'covers', 'groups', 'channels', 'chat_images']
            for folder in folders:
                path = os.path.join('static', 'uploads', folder)
                os.makedirs(path, exist_ok=True)
                print(f"✅ Папка создана: {path}")

            # Создаем папку static
            os.makedirs('static', exist_ok=True)

            # Создаем дефолтные изображения если их нет
            default_images = ['default_avatar.png', 'default_group.png', 'default_channel.png']
            for img in default_images:
                img_path = os.path.join('static', img)
                if not os.path.exists(img_path):
                    # Создаем простой пустой файл
                    with open(img_path, 'wb') as f:
                        f.write(b'')
                    print(f"✅ Создан файл: {img_path}")

            print("✅ Инициализация завершена")

        except Exception as e:
            print(f"❌ Ошибка при инициализации: {e}")
            logger.error(f"Init error: {e}")


if __name__ == "__main__":
    init_app()
    print("🚀 Запуск Kildear Social Network...")
    print(f"🌐 Сервер доступен по адресу: http://192.168.4.2:5000")
    print("📝 Для остановки сервера нажмите Ctrl+C")

    socketio.run(app,
                 debug=True,
                 host="0.0.0.0",
                 port=5000,
                 allow_unsafe_werkzeug=True)