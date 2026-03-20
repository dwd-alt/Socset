"""
Kildear Social Network — Complete Version
Full-featured backend with admin panel, voice messages, calls, and enhanced security
Images stored in database as Base64
"""

import os
import re
import time
import uuid
import html
import base64
import logging
import platform
from io import BytesIO
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

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
from werkzeug.utils import secure_filename
from sqlalchemy import or_, func, and_, text
from PIL import Image
import bcrypt

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
#  App Configuration
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Определяем окружение
is_production = os.environ.get('RENDER') == 'true' or os.environ.get('FLASK_ENV') == 'production'
is_render = os.environ.get('RENDER') == 'true'
is_windows = platform.system() == 'Windows'

# Определяем базовую директорию
basedir = os.path.abspath(os.path.dirname(__file__))

# Настройка базы данных
if is_render:
    database_url = os.environ.get('DATABASE_URL', '')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    if '?' in database_url:
        SQLALCHEMY_DATABASE_URI = database_url + '&sslmode=require'
    else:
        SQLALCHEMY_DATABASE_URI = database_url + '?sslmode=require'
else:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'kildear.db')

# Настройки для загрузки файлов
if is_render:
    UPLOAD_FOLDER = '/tmp/uploads'  # Только для временных файлов
else:
    UPLOAD_FOLDER = os.path.join('static', 'uploads')

UPLOAD_SUBFOLDERS = ['avatars', 'images', 'videos', 'covers', 'groups',
                     'channels', 'chat_images', 'group_covers', 'channel_covers',
                     'voice_messages']

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
        "pool_size": 20,
        "max_overflow": 40
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
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_mgr = LoginManager(app)
login_mgr.login_view = "login"
login_mgr.login_message = "Пожалуйста, войдите для доступа к этой странице."
login_mgr.login_message_category = "info"

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute", "2000 per hour"],
    storage_uri="memory://" if is_render else "memory://",
)

# Socket.IO
if is_render:
    async_mode = 'eventlet'
elif is_windows:
    async_mode = 'threading'
else:
    async_mode = 'eventlet'

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode=async_mode,
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=10e6
)


# ──────────────────────────────────────────────────────────────────────────────
#  Image Processing Helper
# ──────────────────────────────────────────────────────────────────────────────
def process_image(file, max_size=(800, 800), quality=85):
    """
    Обрабатывает изображение: ресайз, оптимизация, конвертация в JPEG
    Возвращает Base64 строку и MIME тип
    """
    if not file or not file.filename:
        return None, None

    try:
        # Проверяем расширение
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in ALLOWED_IMAGE:
            return None, None

        # Открываем изображение
        img = Image.open(file)

        # Конвертируем в RGB если нужно (для JPEG)
        if img.mode in ('RGBA', 'LA', 'P'):
            bg = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                bg.paste(img, mask=img.split()[3])
            else:
                bg.paste(img)
            img = bg
        elif img.mode != 'RGB':
            img = img.convert('RGB')

        # Ресайз
        img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Сохраняем в BytesIO
        output = BytesIO()
        img.save(output, format='JPEG', quality=quality, optimize=True)
        output.seek(0)

        # Конвертируем в Base64
        image_data = output.read()
        base64_data = base64.b64encode(image_data).decode('utf-8')

        return base64_data, 'image/jpeg'

    except Exception as e:
        logger.error(f"Image processing error: {e}")
        return None, None


def process_image_from_bytes(image_bytes, max_size=(800, 800), quality=85):
    """Обрабатывает изображение из байтов"""
    try:
        img = Image.open(BytesIO(image_bytes))

        # Конвертируем в RGB если нужно
        if img.mode in ('RGBA', 'LA', 'P'):
            bg = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                bg.paste(img, mask=img.split()[3])
            else:
                bg.paste(img)
            img = bg
        elif img.mode != 'RGB':
            img = img.convert('RGB')

        # Ресайз
        img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Сохраняем
        output = BytesIO()
        img.save(output, format='JPEG', quality=quality, optimize=True)
        output.seek(0)

        return output.read(), 'image/jpeg'

    except Exception as e:
        logger.error(f"Image processing from bytes error: {e}")
        return None, None


def save_image_to_db(file, max_size=(800, 800), quality=85):
    """
    Сохраняет изображение в базу данных (Base64)
    Возвращает Data URL
    """
    if not file or not file.filename:
        return None

    base64_data, mime_type = process_image(file, max_size, quality)
    if base64_data:
        return f"data:{mime_type};base64,{base64_data}"
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  Template Filters
# ──────────────────────────────────────────────────────────────────────────────
@app.template_filter('timeago')
def timeago_filter(date):
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
    return date.strftime(format) if date else ''


@app.template_filter('format_time')
def format_time_filter(date, format='%H:%M'):
    return date.strftime(format) if date else ''


# ──────────────────────────────────────────────────────────────────────────────
#  Декоратор для проверки прав администратора
# ──────────────────────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


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

    # Хранение изображений в БД как Base64
    avatar_data = db.Column(db.Text, nullable=True)
    avatar_mime = db.Column(db.String(50), default="image/png")
    cover_data = db.Column(db.Text, nullable=True)
    cover_mime = db.Column(db.String(50), default="image/jpeg")

    # Для обратной совместимости
    avatar = db.Column(db.String(300), default="/static/default_avatar.png")
    cover_photo = db.Column(db.String(300), default="")

    website = db.Column(db.String(200), default="")
    location = db.Column(db.String(100), default="")
    accent_color = db.Column(db.String(7), default="#6c63ff")
    is_private = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

    # Отношения
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
    login_history = db.relationship("LoginHistory", backref="user", lazy="dynamic")

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

    @property
    def avatar_url(self):
        """Получить URL аватара (из БД или по умолчанию)"""
        if self.avatar_data:
            return f"data:{self.avatar_mime};base64,{self.avatar_data}"
        return self.avatar or "/static/default_avatar.png"

    @property
    def cover_url(self):
        """Получить URL обложки (из БД или пусто)"""
        if self.cover_data:
            return f"data:{self.cover_mime};base64,{self.cover_data}"
        return self.cover_photo or ""

    def set_avatar(self, image_data, mime_type="image/png"):
        """Установить аватар из бинарных данных"""
        self.avatar_data = base64.b64encode(image_data).decode('utf-8')
        self.avatar_mime = mime_type
        self.avatar = ""

    def set_cover(self, image_data, mime_type="image/jpeg"):
        """Установить обложку из бинарных данных"""
        self.cover_data = base64.b64encode(image_data).decode('utf-8')
        self.cover_mime = mime_type
        self.cover_photo = ""

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


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # nullable=True для неудачных попыток
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(200))
    location = db.Column(db.String(100))
    success = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class VoiceMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    audio_data = db.Column(db.Text, nullable=False)  # Base64 данные аудио
    audio_mime = db.Column(db.String(50), default="audio/mpeg")
    audio_url = db.Column(db.String(300), default="")
    duration = db.Column(db.Integer, default=0)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def audio_url_data(self):
        if self.audio_data:
            return f"data:{self.audio_mime};base64,{self.audio_data}"
        return self.audio_url

    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_voice_msgs")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_voice_msgs")


class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    callee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    call_type = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='missed')
    duration = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)

    caller = db.relationship("User", foreign_keys=[caller_id])
    callee = db.relationship("User", foreign_keys=[callee_id])


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=True)
    reason = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    reported_user = db.relationship("User", foreign_keys=[reported_user_id])
    reviewer = db.relationship("User", foreign_keys=[reviewed_by])


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, default="")

    # Хранение медиа в БД
    media_data = db.Column(db.Text, nullable=True)
    media_mime = db.Column(db.String(50), nullable=True)

    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    thumbnail = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)

    liked_by = db.relationship("User", secondary=post_likes, backref="liked_posts", lazy="dynamic")
    comments = db.relationship("Comment", backref="post", lazy="dynamic", cascade="all,delete")

    @property
    def media_url_data(self):
        if self.media_data:
            return f"data:{self.media_mime};base64,{self.media_data}"
        return self.media_url

    def set_media(self, media_data, mime_type, media_type="image"):
        self.media_data = base64.b64encode(media_data).decode('utf-8')
        self.media_mime = mime_type
        self.media_type = media_type
        self.media_url = ""

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
    media_data = db.Column(db.Text, nullable=True)
    media_mime = db.Column(db.String(50), nullable=True)
    media_url = db.Column(db.String(300), default="")
    is_read = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def media_url_data(self):
        if self.media_data:
            return f"data:{self.media_mime};base64,{self.media_data}"
        return self.media_url

    replies = db.relationship("Message", backref=db.backref("reply_to", remote_side=[id]))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar_data = db.Column(db.Text, nullable=True)
    avatar_mime = db.Column(db.String(50), default="image/png")
    cover_data = db.Column(db.Text, nullable=True)
    cover_mime = db.Column(db.String(50), default="image/jpeg")
    avatar = db.Column(db.String(300), default="/static/default_group.png")
    cover = db.Column(db.String(300), default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def avatar_url(self):
        if self.avatar_data:
            return f"data:{self.avatar_mime};base64,{self.avatar_data}"
        return self.avatar

    @property
    def cover_url(self):
        if self.cover_data:
            return f"data:{self.cover_mime};base64,{self.cover_data}"
        return self.cover

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
    media_data = db.Column(db.Text, nullable=True)
    media_mime = db.Column(db.String(50), nullable=True)
    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def media_url_data(self):
        if self.media_data:
            return f"data:{self.media_mime};base64,{self.media_data}"
        return self.media_url

    author = db.relationship("User")


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    avatar_data = db.Column(db.Text, nullable=True)
    avatar_mime = db.Column(db.String(50), default="image/png")
    cover_data = db.Column(db.Text, nullable=True)
    cover_mime = db.Column(db.String(50), default="image/jpeg")
    avatar = db.Column(db.String(300), default="/static/default_channel.png")
    cover = db.Column(db.String(300), default="")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_nsfw = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def avatar_url(self):
        if self.avatar_data:
            return f"data:{self.avatar_mime};base64,{self.avatar_data}"
        return self.avatar

    @property
    def cover_url(self):
        if self.cover_data:
            return f"data:{self.cover_mime};base64,{self.cover_data}"
        return self.cover

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
    media_data = db.Column(db.Text, nullable=True)
    media_mime = db.Column(db.String(50), nullable=True)
    media_url = db.Column(db.String(300), default="")
    media_type = db.Column(db.String(20), default="text")
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def media_url_data(self):
        if self.media_data:
            return f"data:{self.media_mime};base64,{self.media_data}"
        return self.media_url


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
#  Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def notification_link(notif):
    if notif.type in ['like', 'comment', 'mention']:
        if notif.post_id:
            return url_for('view_post', post_id=notif.post_id)
    elif notif.type == 'follow':
        if notif.from_user:
            return url_for('profile', username=notif.from_user.username)
    elif notif.type in ['missed_call', 'incoming_call', 'voice_message']:
        if notif.from_user:
            return url_for('chat', username=notif.from_user.username)
    return '#'


def notification_icon(notif):
    icons = {
        'like': '❤️',
        'comment': '💬',
        'follow': '👤',
        'mention': '@',
        'group_post': '👥',
        'channel_post': '📢',
        'missed_call': '📞',
        'incoming_call': '📞',
        'voice_message': '🎤',
        'message': '💬'
    }
    return icons.get(notif.type, '🔔')


def notification_text(notif):
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
    elif notif.type == 'group_post':
        return f"New post in group"
    elif notif.type == 'channel_post':
        return f"New post in channel"
    elif notif.type == 'missed_call':
        return f"Missed call from {notif.from_user.username}"
    elif notif.type == 'voice_message':
        return f"Voice message from {notif.from_user.username}"
    elif notif.type == 'message':
        return f"New message from {notif.from_user.username}"
    return "New notification"


def allowed_file(filename: str, allowed: set) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def ensure_upload_folders():
    for folder in UPLOAD_SUBFOLDERS:
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
        try:
            os.makedirs(folder_path, exist_ok=True)
            logger.info(f"✅ Folder ready: {folder_path}")
        except Exception as e:
            logger.error(f"❌ Failed to create folder {folder_path}: {e}")


def save_file(file, subfolder: str):
    """Сохраняет файл (для видео и аудио)"""
    if not file or not file.filename:
        return None
    try:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if not ext:
            return None
        if ext not in ALLOWED_VIDEO and ext not in ALLOWED_AUDIO:
            return None
        filename = f"{uuid.uuid4().hex}.{ext}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(upload_path, exist_ok=True)
        file_path = os.path.join(upload_path, filename)
        file.save(file_path)
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            logger.error(f"❌ File not saved properly: {file_path}")
            return None
        logger.info(f"✅ File saved: {file_path}")
        if is_render:
            return f"/uploads/{subfolder}/{filename}"
        else:
            return f"/static/uploads/{subfolder}/{filename}"
    except Exception as e:
        logger.error(f"❌ Error saving file: {e}")
        return None


def save_image(file, subfolder=None):
    """Сохраняет изображение в базу данных (Base64)"""
    if not file or not file.filename:
        return None

    try:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in ALLOWED_IMAGE:
            return None

        # Проверяем размер
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)

        if size > 5 * 1024 * 1024:  # 5MB max
            return None

        # Обрабатываем изображение
        base64_data, mime_type = process_image(file)
        if base64_data:
            return f"data:{mime_type};base64,{base64_data}"
        return None

    except Exception as e:
        logger.error(f"Error saving image: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  Маршрут для доступа к загруженным файлам
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/uploads/<path:subfolder>/<path:filename>')
def serve_upload(subfolder, filename):
    if subfolder not in UPLOAD_SUBFOLDERS:
        abort(404)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder, filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_from_directory(
        os.path.join(app.config['UPLOAD_FOLDER'], subfolder),
        filename
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Report Routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/report/user/<int:user_id>", methods=["GET", "POST"])
@login_required
def report_user(user_id):
    reported_user = User.query.get_or_404(user_id)

    if reported_user.id == current_user.id:
        flash("Нельзя пожаловаться на самого себя", "error")
        return redirect(url_for("profile", username=reported_user.username))

    if request.method == "POST":
        reason = request.form.get("reason")
        description = request.form.get("description", "")

        if not reason:
            flash("Укажите причину жалобы", "error")
            return redirect(url_for("report_user", user_id=user_id))

        report = Report(
            reporter_id=current_user.id,
            reported_user_id=reported_user.id,
            reason=reason,
            description=description,
            status='pending'
        )
        db.session.add(report)
        db.session.commit()

        flash(f"Жалоба на пользователя {reported_user.username} отправлена", "success")
        return redirect(url_for("profile", username=reported_user.username))

    reasons = [
        ("spam", "Спам"),
        ("harassment", "Домогательство"),
        ("hate_speech", "Разжигание ненависти"),
        ("violence", "Насилие"),
        ("scam", "Мошенничество"),
        ("fake_account", "Фейковый аккаунт"),
        ("other", "Другое")
    ]

    return render_template("report_user.html", user=reported_user, reasons=reasons)


@app.route("/report/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def report_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id == current_user.id:
        flash("Нельзя пожаловаться на свой пост", "error")
        return redirect(url_for("view_post", post_id=post_id))

    if request.method == "POST":
        reason = request.form.get("reason")
        description = request.form.get("description", "")

        if not reason:
            flash("Укажите причину жалобы", "error")
            return redirect(url_for("report_post", post_id=post_id))

        report = Report(
            reporter_id=current_user.id,
            reported_user_id=post.user_id,
            post_id=post.id,
            reason=reason,
            description=description,
            status='pending'
        )
        db.session.add(report)
        db.session.commit()

        flash(f"Жалоба на пост отправлена", "success")
        return redirect(url_for("view_post", post_id=post_id))

    reasons = [
        ("spam", "Спам"),
        ("harassment", "Домогательство"),
        ("hate_speech", "Разжигание ненависти"),
        ("violence", "Насилие"),
        ("nsfw", "Неприемлемый контент"),
        ("copyright", "Нарушение авторских прав"),
        ("other", "Другое")
    ]

    return render_template("report_post.html", post=post, reasons=reasons)


@app.route("/report/comment/<int:comment_id>", methods=["GET", "POST"])
@login_required
def report_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if comment.user_id == current_user.id:
        flash("Нельзя пожаловаться на свой комментарий", "error")
        return redirect(url_for("view_post", post_id=comment.post_id))

    if request.method == "POST":
        reason = request.form.get("reason")
        description = request.form.get("description", "")

        if not reason:
            flash("Укажите причину жалобы", "error")
            return redirect(url_for("report_comment", comment_id=comment_id))

        report = Report(
            reporter_id=current_user.id,
            reported_user_id=comment.user_id,
            comment_id=comment.id,
            reason=reason,
            description=description,
            status='pending'
        )
        db.session.add(report)
        db.session.commit()

        flash(f"Жалоба на комментарий отправлена", "success")
        return redirect(url_for("view_post", post_id=comment.post_id))

    return render_template("report_comment.html", comment=comment)


# ──────────────────────────────────────────────────────────────────────────────
#  DDoS Protection
# ──────────────────────────────────────────────────────────────────────────────
_req_log: dict = defaultdict(list)
_blocked_ips: set = set()
_fail_log: dict = defaultdict(list)


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


@app.before_request
def ddos_shield():
    ip = get_client_ip()
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
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    csp = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "font-src 'self' https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "connect-src 'self' wss: ws:",
        "frame-ancestors 'none'"
    ]
    response.headers["Content-Security-Policy"] = '; '.join(csp)
    return response


def track_failure(ip: str):
    now = time.time()
    fails = [t for t in _fail_log[ip] if now - t < 300]
    fails.append(now)
    _fail_log[ip] = fails
    if len(fails) >= 20:
        _blocked_ips.add(ip)


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
    stats = {}

    if current_user.is_authenticated:
        unread = Message.query.filter_by(
            receiver_id=current_user.id, is_read=False, is_deleted=False).count()
        notif_count = Notification.query.filter_by(
            user_id=current_user.id, is_read=False).count()

        if current_user.is_admin:
            stats['total_reports'] = Report.query.filter_by(status='pending').count()
            stats['pending_verification'] = User.query.filter_by(is_verified=False, is_banned=False).count()
            stats['banned_users'] = User.query.filter_by(is_banned=True).count()

    return dict(
        unread_messages=unread,
        notif_count=notif_count,
        stats=stats,
        csrf_token=generate_csrf,
        notification_link=notification_link,
        notification_icon=notification_icon,
        notification_text=notification_text,
        now=datetime.utcnow(),
        is_production=is_production
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
    voice_count = VoiceMessage.query.filter_by(
        receiver_id=current_user.id, is_read=False).count()
    return jsonify({
        "notifications": notif_count,
        "messages": msg_count,
        "voice_messages": voice_count
    })


@app.route("/api/mark_notification_read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.filter_by(id=notif_id, user_id=current_user.id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Notification not found"}), 404


@app.route("/api/mark_all_notifications_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"success": True})


# ──────────────────────────────────────────────────────────────────────────────
#  Admin Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    stats = {
        "total_users": User.query.count(),
        "total_posts": Post.query.count(),
        "total_comments": Comment.query.count(),
        "total_reports": Report.query.filter_by(status='pending').count(),
        "new_users_today": User.query.filter(
            User.created_at >= datetime.utcnow().date()
        ).count(),
        "banned_users": User.query.filter_by(is_banned=True).count(),
        "images_in_db": User.query.filter(User.avatar_data.isnot(None)).count() +
                         Post.query.filter(Post.media_data.isnot(None)).count()
    }

    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    pending_reports = Report.query.filter_by(status='pending').order_by(
        Report.created_at.desc()
    ).limit(20).all()
    recent_logins = LoginHistory.query.order_by(
        LoginHistory.created_at.desc()
    ).limit(20).all()

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_users=recent_users,
        pending_reports=pending_reports,
        recent_logins=recent_logins
    )


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "")

    query = User.query
    if search:
        query = query.filter(
            or_(
                User.username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
                User.display_name.ilike(f"%{search}%")
            )
        )

    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template("admin/users.html", users=users, search=search)


@app.route("/admin/user/<int:user_id>/toggle-ban", methods=["POST"])
@login_required
@admin_required
def admin_toggle_ban(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя забанить самого себя", "error")
        return redirect(url_for("admin_users"))

    user.is_banned = not user.is_banned
    db.session.commit()

    status = "забанен" if user.is_banned else "разбанен"
    flash(f"Пользователь {user.username} {status}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя изменить свои права администратора", "error")
        return redirect(url_for("admin_users"))

    user.is_admin = not user.is_admin
    db.session.commit()

    status = "назначен администратором" if user.is_admin else "лишен прав администратора"
    flash(f"Пользователь {user.username} {status}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/toggle-verify", methods=["POST"])
@login_required
@admin_required
def admin_toggle_verify(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()

    status = "верифицирован" if user.is_verified else "снята верификация"
    flash(f"Пользователь {user.username} {status}", "success")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя", "error")
        return redirect(url_for("admin_users"))

    username = user.username
    db.session.delete(user)
    db.session.commit()

    flash(f"Пользователь {username} полностью удален", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/reports")
@login_required
@admin_required
def admin_reports():
    status = request.args.get("status", "pending")

    query = Report.query
    if status != "all":
        query = query.filter_by(status=status)

    reports = query.order_by(Report.created_at.desc()).all()
    return render_template("admin/reports.html", reports=reports, current_status=status)


@app.route("/admin/report/<int:report_id>/review", methods=["POST"])
@login_required
@admin_required
def admin_review_report(report_id):
    report = Report.query.get_or_404(report_id)
    action = request.form.get("action")

    if action == "dismiss":
        report.status = "dismissed"
        flash("Жалоба отклонена", "success")
    elif action == "approve":
        report.status = "reviewed"
        if report.reported_user_id:
            user = User.query.get(report.reported_user_id)
            if user:
                user.is_banned = True
                flash(f"Пользователь {user.username} забанен", "success")

    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_user.id
    db.session.commit()

    return redirect(url_for("admin_reports"))


@app.route("/admin/verification")
@login_required
@admin_required
def admin_verification():
    page = request.args.get("page", 1, type=int)
    users = User.query.filter_by(is_verified=False, is_banned=False).order_by(User.created_at.desc()).paginate(
        page=page, per_page=20)
    return render_template("admin/verification.html", users=users)


@app.route("/admin/banned")
@login_required
@admin_required
def admin_banned():
    page = request.args.get("page", 1, type=int)
    users = User.query.filter_by(is_banned=True).order_by(User.last_seen.desc()).paginate(page=page, per_page=20)
    return render_template("admin/banned.html", users=users)


@app.route("/admin/admins")
@login_required
@admin_required
def admin_admins():
    admins = User.query.filter_by(is_admin=True).order_by(User.created_at).all()
    return render_template("admin/admins.html", admins=admins)


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    page = request.args.get("page", 1, type=int)
    logs = LoginHistory.query.order_by(LoginHistory.created_at.desc()).paginate(page=page, per_page=50)
    return render_template("admin/logs.html", logs=logs)


# ──────────────────────────────────────────────────────────────────────────────
#  Voice Message Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/voice/send", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def send_voice_message():
    try:
        receiver_id = request.form.get("receiver_id", type=int)
        audio_file = request.files.get("audio")

        if not audio_file or not audio_file.filename:
            return jsonify({"error": "No audio file provided"}), 400

        receiver = User.query.get_or_404(receiver_id)

        if current_user.is_blocked(receiver):
            return jsonify({"error": "Cannot send message to blocked user"}), 403

        ext = audio_file.filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_AUDIO:
            return jsonify({"error": "Audio format not supported"}), 400

        # Сохраняем аудио в БД
        audio_file.seek(0)
        audio_data = audio_file.read()
        base64_data = base64.b64encode(audio_data).decode('utf-8')

        duration = request.form.get("duration", 0, type=int)

        voice_msg = VoiceMessage(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            audio_data=base64_data,
            audio_mime=f"audio/{ext}",
            duration=duration
        )
        db.session.add(voice_msg)
        db.session.commit()

        notif = Notification(
            user_id=receiver.id,
            from_user_id=current_user.id,
            type="voice_message",
            text=f"Voice message from {current_user.username}"
        )
        db.session.add(notif)
        db.session.commit()

        room = "_".join(sorted([str(current_user.id), str(receiver.id)]))
        socketio.emit("new_voice_message", {
            "id": voice_msg.id,
            "sender_id": current_user.id,
            "sender_username": current_user.username,
            "sender_avatar": current_user.avatar_url,
            "audio_url": voice_msg.audio_url_data,
            "duration": voice_msg.duration,
            "created_at": voice_msg.created_at.strftime("%H:%M")
        }, room=room)

        send_notification(receiver.id, {
            "type": "voice_message",
            "from_user": {
                "id": current_user.id,
                "username": current_user.username,
                "avatar": current_user.avatar_url
            },
            "text": f"Voice message from {current_user.username}"
        })

        return jsonify({"success": True, "id": voice_msg.id})

    except Exception as e:
        logger.error(f"Error sending voice message: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/voice/<int:message_id>")
@login_required
def get_voice_message(message_id):
    msg = VoiceMessage.query.get_or_404(message_id)

    if msg.sender_id != current_user.id and msg.receiver_id != current_user.id:
        abort(403)

    return jsonify({
        "id": msg.id,
        "sender_id": msg.sender_id,
        "audio_url": msg.audio_url_data,
        "duration": msg.duration,
        "created_at": msg.created_at.isoformat(),
        "is_read": msg.is_read
    })


@app.route("/voice/mark-read/<int:message_id>", methods=["POST"])
@login_required
def mark_voice_read(message_id):
    msg = VoiceMessage.query.get_or_404(message_id)
    if msg.receiver_id == current_user.id:
        msg.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Not authorized"}), 403


# ──────────────────────────────────────────────────────────────────────────────
#  Call Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/call/start", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def start_call():
    try:
        data = request.get_json()
        callee_id = data.get('callee_id')
        call_type = data.get('type', 'audio')

        callee = User.query.get_or_404(callee_id)

        if current_user.is_blocked(callee):
            return jsonify({"error": "Cannot call blocked user"}), 403

        existing_call = Call.query.filter(
            and_(
                or_(
                    and_(Call.caller_id == callee_id, Call.status == 'ongoing'),
                    and_(Call.callee_id == callee_id, Call.status == 'ongoing')
                )
            )
        ).first()

        if existing_call:
            return jsonify({"error": "User is already in a call"}), 409

        call = Call(
            caller_id=current_user.id,
            callee_id=callee.id,
            call_type=call_type,
            status='ongoing'
        )
        db.session.add(call)
        db.session.commit()

        webrtc_config = {
            'iceServers': [
                {'urls': 'stun:stun.l.google.com:19302'},
                {'urls': 'stun:stun1.l.google.com:19302'},
                {'urls': 'stun:stun2.l.google.com:19302'},
                {'urls': 'stun:stun3.l.google.com:19302'},
                {'urls': 'stun:stun4.l.google.com:19302'}
            ]
        }

        room = f"user_{callee.id}"
        socketio.emit("incoming_call", {
            "call_id": call.id,
            "caller_id": current_user.id,
            "caller_username": current_user.username,
            "caller_avatar": current_user.avatar_url,
            "type": call_type,
            "webrtc_config": webrtc_config
        }, room=room)

        return jsonify({
            "success": True,
            "call_id": call.id,
            "webrtc_config": webrtc_config
        })

    except Exception as e:
        logger.error(f"Error starting call: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/call/<int:call_id>/accept", methods=["POST"])
@login_required
def accept_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403

    call.status = 'ongoing'
    call.started_at = datetime.utcnow()
    db.session.commit()

    room = f"user_{call.caller_id}"
    socketio.emit("call_accepted", {
        "call_id": call.id,
        "accepted_by": current_user.id
    }, room=room)

    return jsonify({"success": True})


@app.route("/call/<int:call_id>/reject", methods=["POST"])
@login_required
def reject_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403

    call.status = 'rejected'
    call.ended_at = datetime.utcnow()
    db.session.commit()

    room = f"user_{call.caller_id}"
    socketio.emit("call_rejected", {
        "call_id": call.id,
        "rejected_by": current_user.id
    }, room=room)

    return jsonify({"success": True})


@app.route("/call/<int:call_id>/end", methods=["POST"])
@login_required
def end_call(call_id):
    call = Call.query.get_or_404(call_id)

    if call.caller_id != current_user.id and call.callee_id != current_user.id:
        return jsonify({"error": "Not authorized"}), 403

    call.status = 'completed'
    call.ended_at = datetime.utcnow()

    if call.started_at:
        duration = (call.ended_at - call.started_at).seconds
        call.duration = duration

    db.session.commit()

    other_id = call.caller_id if call.callee_id == current_user.id else call.callee_id
    room = f"user_{other_id}"
    socketio.emit("call_ended", {
        "call_id": call.id,
        "ended_by": current_user.id,
        "duration": call.duration
    }, room=room)

    return jsonify({"success": True})


@app.route("/call/history")
@login_required
def call_history():
    calls = Call.query.filter(
        or_(
            Call.caller_id == current_user.id,
            Call.callee_id == current_user.id
        )
    ).order_by(Call.started_at.desc()).limit(50).all()

    call_list = []
    for call in calls:
        other = User.query.get(call.caller_id if call.callee_id == current_user.id else call.callee_id)
        call_list.append({
            "id": call.id,
            "other_user": {
                "id": other.id,
                "username": other.username,
                "display_name": other.display_name,
                "avatar": other.avatar_url
            },
            "type": call.call_type,
            "status": call.status,
            "duration": call.duration,
            "started_at": call.started_at.isoformat(),
            "is_outgoing": call.caller_id == current_user.id
        })

    return jsonify({"calls": call_list})


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
                flash("Имя пользователя должно быть 3-40 символов и содержать только буквы, цифры и подчеркивания", "error")
                return render_template("register.html")

            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
                flash("Неверный формат email", "error")
                return render_template("register.html")

            if len(password) < 8:
                flash("Пароль должен быть не менее 8 символов", "error")
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
                is_banned=False
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
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')

        user = User.query.filter(
            or_(func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower())
        ).first()

        login_success = False

        if user and user.check_password(password) and not user.is_banned:
            login_user(user, remember=remember)
            session.permanent = remember

            user.is_online = True
            user.last_seen = datetime.utcnow()

            login_success = True
            flash(f"С возвращением, {user.username}! 👋", "success")
        else:
            track_failure(ip)
            flash("Неверные учетные данные.", "error")

        # Сохраняем историю входа (с user_id=None для неудачных попыток)
        try:
            login_history = LoginHistory(
                user_id=user.id if user else None,
                ip_address=ip,
                user_agent=user_agent[:200],
                location=None,
                success=login_success
            )
            db.session.add(login_history)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to save login history: {e}")
            db.session.rollback()

        if login_success:
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

    blocked_ids = [b.id for b in current_user.blocked_users]

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

            if ext in ALLOWED_VIDEO:
                media_url = save_file(media_file, "videos") or ""
                media_type = "video"
            elif ext in ALLOWED_IMAGE:
                # Сохраняем изображение в БД
                image_url = save_image(media_file)
                if image_url:
                    media_url = image_url
                    media_type = "image"
                else:
                    media_url = save_file(media_file, "images") or ""
                    media_type = "image" if media_url else "text"
            else:
                flash(f"Неподдерживаемый тип файла", "error")
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
            send_notification(post.user_id, {
                "type": "like",
                "from_user": {
                    "id": current_user.id,
                    "username": current_user.username,
                    "avatar": current_user.avatar_url
                },
                "post_id": post.id,
                "text": f"{current_user.username} liked your post"
            })

    db.session.commit()
    return jsonify({"liked": liked, "count": post.like_count})


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)

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
        send_notification(post.user_id, {
            "type": "comment",
            "from_user": {
                "id": current_user.id,
                "username": current_user.username,
                "avatar": current_user.avatar_url
            },
            "post_id": post.id,
            "comment": content[:50],
            "text": f"{current_user.username} commented on your post"
        })

    db.session.commit()

    return jsonify({
        "id": c.id,
        "username": current_user.username,
        "avatar": current_user.avatar_url,
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

    is_blocked = current_user.is_blocked(user) if user.id != current_user.id else False

    page = request.args.get("page", 1, type=int)
    tab = request.args.get("tab", "posts")

    if is_blocked:
        posts = []
        videos = []
    else:
        posts = (user.posts.order_by(Post.created_at.desc())
                 .paginate(page=page, per_page=12, error_out=False))
        videos = (user.posts.filter_by(media_type="video")
                  .order_by(Post.created_at.desc()).limit(12).all())

    is_own = user.id == current_user.id
    is_following = current_user.is_following(user) if not is_own else False

    return render_template("profile.html", user=user, posts=posts,
                           videos=videos, is_own=is_own,
                           is_following=is_following, is_blocked=is_blocked,
                           tab=tab)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        try:
            current_user.display_name = request.form.get("display_name", "")[:60]
            current_user.bio = request.form.get("bio", "")[:500]
            current_user.website = request.form.get("website", "")[:200]
            current_user.location = request.form.get("location", "")[:100]
            current_user.accent_color = request.form.get("accent_color", "#6c63ff")[:7]
            current_user.is_private = bool(request.form.get("is_private"))

            # Обработка аватара (сохраняем в БД)
            avatar = request.files.get("avatar")
            if avatar and avatar.filename:
                avatar.seek(0, 2)
                file_size = avatar.tell()
                avatar.seek(0)

                if file_size > 5 * 1024 * 1024:
                    flash("Avatar file too large. Maximum size is 5MB.", "error")
                else:
                    image_url = save_image(avatar)
                    if image_url:
                        current_user.avatar = image_url
                        # Очищаем старые данные
                        current_user.avatar_data = None
                        flash("Avatar updated successfully!", "success")
                    else:
                        flash("Failed to upload avatar. Please try again.", "error")

            # Обработка обложки (сохраняем в БД)
            cover = request.files.get("cover_photo")
            if cover and cover.filename:
                cover.seek(0, 2)
                file_size = cover.tell()
                cover.seek(0)

                if file_size > 10 * 1024 * 1024:
                    flash("Cover photo too large. Maximum size is 10MB.", "error")
                else:
                    image_url = save_image(cover)
                    if image_url:
                        current_user.cover_photo = image_url
                        # Очищаем старые данные
                        current_user.cover_data = None
                        flash("Cover photo updated successfully!", "success")
                    else:
                        flash("Failed to upload cover photo. Please try again.", "error")

            db.session.commit()
            flash("Profile updated successfully!", "success")

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating profile: {e}")
            flash(f"Error updating profile: {str(e)}", "error")

        return redirect(url_for("profile", username=current_user.username))

    return render_template("edit_profile.html")


@app.route("/follow/<username>", methods=["POST"])
@login_required
def follow(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    if user.id == current_user.id:
        return jsonify({"error": "Cannot follow yourself."}), 400

    if current_user.is_blocked(user):
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
        send_notification(user.id, {
            "type": "follow",
            "from_user": {
                "id": current_user.id,
                "username": current_user.username,
                "avatar": current_user.avatar_url
            },
            "text": f"{current_user.username} started following you"
        })

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

    blocked_ids = [b.id for b in current_user.blocked_users]

    videos = (Post.query.filter_by(media_type="video")
              .filter(Post.user_id.notin_(blocked_ids))
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

    if q.startswith('@'):
        q = q[1:]

    users = []
    posts = []
    groups = []
    channels = []

    blocked_ids = [b.id for b in current_user.blocked_users]

    if q:
        pattern = f"%{q}%"
        users = User.query.filter(
            or_(
                User.username.ilike(pattern),
                User.display_name.ilike(pattern)
            )
        ).filter(User.id != current_user.id) \
            .filter(User.id.notin_(blocked_ids)) \
            .limit(20).all()

        posts = Post.query.filter(Post.content.ilike(pattern)) \
            .filter(Post.user_id.notin_(blocked_ids)) \
            .limit(20).all()

        groups = Group.query.filter(
            or_(Group.name.ilike(pattern),
                Group.description.ilike(pattern))).limit(10).all()

        channels = Channel.query.filter(
            or_(Channel.name.ilike(pattern),
                Channel.description.ilike(pattern))).limit(10).all()

    if request.args.get("ajax") == "1" or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "users": [{
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
                "avatar": u.avatar_url,
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
    try:
        sent_to = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set = {r[0] for r in sent_to} | {r[0] for r in recv_from}

        blocked_ids = [b.id for b in current_user.blocked_users]
        uid_set = uid_set - set(blocked_ids)

        partners = User.query.filter(User.id.in_(uid_set)).all()

        conversations = []
        for p in partners:
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

            voice_unread = VoiceMessage.query.filter_by(
                sender_id=p.id, receiver_id=current_user.id, is_read=False
            ).count()

            conversations.append({
                "user": p,
                "last": last,
                "unread": unread,
                "voice_unread": voice_unread
            })

        conversations.sort(key=lambda x: x["last"].created_at if x["last"] else datetime.min, reverse=True)
        return render_template("chat_list.html", conversations=conversations)

    except Exception as e:
        logger.error(f"Ошибка в chat_list: {e}")
        flash("Ошибка при загрузке чата", "error")
        return redirect(url_for("index"))


@app.route("/chat/<username>")
@login_required
def chat(username):
    try:
        partner = User.query.filter(
            func.lower(User.username) == username.lower()).first_or_404()

        is_blocked = current_user.is_blocked(partner)

        if not is_blocked:
            Message.query.filter_by(
                sender_id=partner.id, receiver_id=current_user.id, is_read=False
            ).update({"is_read": True})
            VoiceMessage.query.filter_by(
                sender_id=partner.id, receiver_id=current_user.id, is_read=False
            ).update({"is_read": True})
            db.session.commit()

        if is_blocked:
            messages = []
            voice_messages = []
        else:
            messages = (Message.query
                        .filter(or_(
                and_(Message.sender_id == current_user.id, Message.receiver_id == partner.id),
                and_(Message.sender_id == partner.id, Message.receiver_id == current_user.id)
            ))
                        .filter(Message.is_deleted == False)
                        .order_by(Message.created_at.asc()).limit(100).all())

            voice_messages = VoiceMessage.query.filter(
                or_(
                    and_(VoiceMessage.sender_id == current_user.id, VoiceMessage.receiver_id == partner.id),
                    and_(VoiceMessage.sender_id == partner.id, VoiceMessage.receiver_id == current_user.id)
                )
            ).order_by(VoiceMessage.created_at.asc()).limit(50).all()

        sent_to = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
        recv_from = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
        uid_set = {r[0] for r in sent_to} | {r[0] for r in recv_from}

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
                               voice_messages=voice_messages,
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

        if current_user.is_blocked(partner):
            return jsonify({"error": "Cannot send message to blocked user"}), 403

        content = request.form.get("content", "").strip()
        media_file = request.files.get("media")
        media_url = ""
        reply_to_id = request.form.get("reply_to", type=int)

        if media_file and media_file.filename:
            ext = media_file.filename.rsplit('.', 1)[1].lower() if '.' in media_file.filename else ''
            if ext in ALLOWED_IMAGE:
                # Сохраняем изображение в БД
                image_url = save_image(media_file)
                if image_url:
                    media_url = image_url
                else:
                    media_url = save_file(media_file, "chat_images") or ""
            else:
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

        notif = Notification(
            user_id=partner.id,
            from_user_id=current_user.id,
            type="message",
            text=f"{current_user.username} sent you a message"
        )
        db.session.add(notif)
        db.session.commit()

        message_data = {
            "id": msg.id,
            "sender_id": current_user.id,
            "sender_username": current_user.username,
            "sender_avatar": current_user.avatar_url,
            "content": msg.content,
            "media_url": msg.media_url,
            "reply_to_id": msg.reply_to_id,
            "created_at": msg.created_at.strftime("%H:%M"),
        }

        room = "_".join(sorted([str(current_user.id), str(partner.id)]))
        socketio.emit("new_message", message_data, room=room)

        send_notification(partner.id, {
            "type": "message",
            "from_user": {
                "id": current_user.id,
                "username": current_user.username,
                "avatar": current_user.avatar_url
            },
            "text": f"New message from {current_user.username}"
        })

        return jsonify({"ok": True, "id": msg.id})

    except Exception as e:
        logger.error(f"Ошибка в send_message: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/chat/message/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id):
    try:
        msg = Message.query.get_or_404(message_id)

        if msg.sender_id != current_user.id:
            return jsonify({"error": "Cannot delete other's messages"}), 403

        msg.is_deleted = True
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Ошибка при удалении сообщения: {e}")
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

        base_slug = re.sub(r"[^a-z0-9-]", "", name.lower().replace(" ", "-"))
        slug = base_slug[:50] + f"-{uuid.uuid4().hex[:6]}"

        g = Group(
            name=name,
            slug=slug,
            description=desc,
            owner_id=current_user.id,
            is_private=priv
        )

        # Обработка аватара группы
        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            image_url = save_image(avatar)
            if image_url:
                g.avatar = image_url

        # Обработка обложки группы
        cover = request.files.get("cover")
        if cover and cover.filename:
            image_url = save_image(cover)
            if image_url:
                g.cover = image_url

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
        send_group_update(g.id, {
            "type": "member_joined",
            "user_id": current_user.id,
            "username": current_user.username,
            "member_count": g.member_count
        })
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
        send_group_update(g.id, {
            "type": "member_left",
            "user_id": current_user.id,
            "username": current_user.username,
            "member_count": g.member_count
        })

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
            media_url = save_file(media_file, "videos") or ""
            media_type = "video"
        elif ext in ALLOWED_IMAGE:
            image_url = save_image(media_file)
            if image_url:
                media_url = image_url
                media_type = "image"
            else:
                media_url = save_file(media_file, "images") or ""
                media_type = "image" if media_url else "text"

    p = GroupPost(
        group_id=g.id,
        user_id=current_user.id,
        content=content,
        media_url=media_url or "",
        media_type=media_type
    )

    db.session.add(p)
    db.session.commit()

    author_data = {
        "id": current_user.id,
        "username": current_user.username,
        "display_name": current_user.display_name,
        "avatar": current_user.avatar_url
    }

    post_data = {
        "id": p.id,
        "content": p.content,
        "media_url": p.media_url,
        "media_type": p.media_type,
        "created_at": p.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "author": author_data
    }

    group_room = f"group_{g.id}"
    socketio.emit("new_group_post", {
        "group_id": g.id,
        "group_slug": g.slug,
        "group_name": g.name,
        "post": post_data
    }, room=group_room)

    for member in g.members:
        if member.id != current_user.id:
            notif = Notification(
                user_id=member.id,
                from_user_id=current_user.id,
                type="group_post",
                text=f"New post in {g.name}"
            )
            db.session.add(notif)
            send_notification(member.id, {
                "type": "group_post",
                "from_user": author_data,
                "group": {
                    "id": g.id,
                    "name": g.name,
                    "slug": g.slug
                },
                "post": post_data,
                "text": f"New post in {g.name}"
            })

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
            image_url = save_image(avatar)
            if image_url:
                c.avatar = image_url

        cover = request.files.get("cover")
        if cover and cover.filename:
            image_url = save_image(cover)
            if image_url:
                c.cover = image_url

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
        send_channel_update(c.id, {
            "type": "subscriber_left",
            "user_id": current_user.id,
            "username": current_user.username,
            "subscriber_count": c.sub_count
        })
    else:
        c.subscribers.append(current_user)
        subscribed = True
        flash(f"Вы подписались на канал '{c.name}'", "success")
        send_channel_update(c.id, {
            "type": "subscriber_joined",
            "user_id": current_user.id,
            "username": current_user.username,
            "subscriber_count": c.sub_count
        })

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
            media_url = save_file(media_file, "videos") or ""
            media_type = "video"
        elif ext in ALLOWED_IMAGE:
            image_url = save_image(media_file)
            if image_url:
                media_url = image_url
                media_type = "image"
            else:
                media_url = save_file(media_file, "images") or ""
                media_type = "image" if media_url else "text"

    p = ChannelPost(
        channel_id=c.id,
        content=content,
        media_url=media_url or "",
        media_type=media_type
    )

    db.session.add(p)
    db.session.commit()

    post_data = {
        "id": p.id,
        "content": p.content,
        "media_url": p.media_url,
        "media_type": p.media_type,
        "created_at": p.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }

    channel_room = f"channel_{c.id}"
    socketio.emit("new_channel_post", {
        "channel_id": c.id,
        "channel_slug": c.slug,
        "channel_name": c.name,
        "post": post_data
    }, room=channel_room)

    for subscriber in c.subscribers:
        if subscriber.id != current_user.id:
            notif = Notification(
                user_id=subscriber.id,
                from_user_id=current_user.id,
                type="channel_post",
                text=f"New post in {c.name}"
            )
            db.session.add(notif)
            send_notification(subscriber.id, {
                "type": "channel_post",
                "from_user": {
                    "id": current_user.id,
                    "username": current_user.username
                },
                "channel": {
                    "id": c.id,
                    "name": c.name,
                    "slug": c.slug
                },
                "post": post_data,
                "text": f"New post in {c.name}"
            })

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
#  Debug endpoint
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/debug/uploads")
@login_required
def debug_uploads():
    if current_user.username != 'admin':
        abort(403)

    upload_folder = app.config['UPLOAD_FOLDER']
    result = {
        "upload_folder": upload_folder,
        "exists": os.path.exists(upload_folder),
        "is_render": is_render,
        "subfolders": {}
    }

    if os.path.exists(upload_folder):
        for subfolder in UPLOAD_SUBFOLDERS:
            path = os.path.join(upload_folder, subfolder)
            if os.path.exists(path):
                try:
                    files = os.listdir(path)[-20:]
                    result['subfolders'][subfolder] = {
                        "path": path,
                        "exists": True,
                        "writable": os.access(path, os.W_OK),
                        "file_count": len(os.listdir(path)),
                        "recent_files": files
                    }
                except Exception as e:
                    result['subfolders'][subfolder] = {
                        "path": path,
                        "exists": True,
                        "error": str(e)
                    }
            else:
                result['subfolders'][subfolder] = {
                    "path": path,
                    "exists": False
                }

    # Добавляем статистику по изображениям в БД
    result['database_images'] = {
        'users_with_avatar': User.query.filter(User.avatar != "/static/default_avatar.png").count(),
        'users_with_cover': User.query.filter(User.cover_photo != "").count(),
        'posts_with_image': Post.query.filter(Post.media_type == "image").count(),
        'messages_with_image': Message.query.filter(Message.media_url != "").count()
    }

    return jsonify(result)


# ──────────────────────────────────────────────────────────────────────────────
#  WebSocket Helper Functions
# ──────────────────────────────────────────────────────────────────────────────
def send_notification(user_id, notification_data):
    user_room = f"user_{user_id}"
    socketio.emit("new_notification", notification_data, room=user_room)


def send_group_update(group_id, update_data):
    group_room = f"group_{group_id}"
    socketio.emit("group_update", update_data, room=group_room)


def send_channel_update(channel_id, update_data):
    channel_room = f"channel_{channel_id}"
    socketio.emit("channel_update", update_data, room=channel_room)


# ──────────────────────────────────────────────────────────────────────────────
#  Socket.IO Events
# ──────────────────────────────────────────────────────────────────────────────
@socketio.on("connect")
def handle_connect():
    if current_user.is_authenticated:
        logger.info(f"User {current_user.id} connected")
        user_room = f"user_{current_user.id}"
        join_room(user_room)


@socketio.on("disconnect")
def handle_disconnect():
    if current_user.is_authenticated:
        logger.info(f"User {current_user.id} disconnected")
        current_user.is_online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


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


@socketio.on("join_group_room")
def on_join_group(data):
    group_id = data.get("group_id")
    if group_id and current_user.is_authenticated:
        group = Group.query.get(group_id)
        if group and group.members.filter(User.id == current_user.id).count() > 0:
            room = f"group_{group_id}"
            join_room(room)


@socketio.on("leave_group_room")
def on_leave_group(data):
    group_id = data.get("group_id")
    if group_id:
        room = f"group_{group_id}"
        leave_room(room)


@socketio.on("join_channel_room")
def on_join_channel(data):
    channel_id = data.get("channel_id")
    if channel_id and current_user.is_authenticated:
        channel = Channel.query.get(channel_id)
        if channel and channel.subscribers.filter(User.id == current_user.id).count() > 0:
            room = f"channel_{channel_id}"
            join_room(room)


@socketio.on("leave_channel_room")
def on_leave_channel(data):
    channel_id = data.get("channel_id")
    if channel_id:
        room = f"channel_{channel_id}"
        leave_room(room)


@socketio.on("join_user_room")
def on_join_user():
    if current_user.is_authenticated:
        user_room = f"user_{current_user.id}"
        join_room(user_room)


# ──────────────────────────────────────────────────────────────────────────────
#  WebRTC Signaling
# ──────────────────────────────────────────────────────────────────────────────
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
                           msg="File too large. Maximum upload size is 100 MB."), 413


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
#  Create Admin User
# ──────────────────────────────────────────────────────────────────────────────
def create_admin_user():
    """Create first admin user if none exists"""
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
            admin = User(
                username='admin',
                email='admin@kildear.com',
                display_name='Administrator',
                is_admin=True,
                is_verified=True
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            logger.info("✅ Администратор создан")
            logger.info(f"   👤 Username: admin")
            logger.info(f"   🔑 Password: {admin_password}")
            logger.info("   ⚠️  Смените пароль после первого входа!")
        else:
            logger.info("✅ Администратор уже существует")
    except Exception as e:
        logger.error(f"❌ Ошибка при создании администратора: {e}")


# ──────────────────────────────────────────────────────────────────────────────
#  Функция миграции базы данных
# ──────────────────────────────────────────────────────────────────────────────
def run_migrations():
    """Автоматическая миграция базы данных при запуске"""
    try:
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('user')]

        logger.info(f"📊 Текущие колонки в таблице user: {columns}")

        changes = []

        # Добавляем колонки для хранения изображений в БД
        image_columns = [
            ('avatar_data', 'TEXT'),
            ('avatar_mime', 'VARCHAR(50) DEFAULT "image/png"'),
            ('cover_data', 'TEXT'),
            ('cover_mime', 'VARCHAR(50) DEFAULT "image/jpeg"')
        ]

        for col_name, col_type in image_columns:
            if col_name not in columns:
                logger.info(f"➕ Добавление колонки {col_name}...")
                db.session.execute(text(f'ALTER TABLE "user" ADD COLUMN {col_name} {col_type}'))
                changes.append(col_name)

        # Добавляем колонки в post
        try:
            post_columns = [col['name'] for col in inspector.get_columns('post')]
            post_image_columns = [
                ('media_data', 'TEXT'),
                ('media_mime', 'VARCHAR(50)')
            ]
            for col_name, col_type in post_image_columns:
                if col_name not in post_columns:
                    logger.info(f"➕ Добавление колонки {col_name} в post...")
                    db.session.execute(text(f'ALTER TABLE "post" ADD COLUMN {col_name} {col_type}'))
                    changes.append(f"post.{col_name}")
        except Exception as e:
            logger.warning(f"Could not migrate post table: {e}")

        # Добавляем колонки в message
        try:
            msg_columns = [col['name'] for col in inspector.get_columns('message')]
            msg_image_columns = [
                ('media_data', 'TEXT'),
                ('media_mime', 'VARCHAR(50)')
            ]
            for col_name, col_type in msg_image_columns:
                if col_name not in msg_columns:
                    logger.info(f"➕ Добавление колонки {col_name} в message...")
                    db.session.execute(text(f'ALTER TABLE "message" ADD COLUMN {col_name} {col_type}'))
                    changes.append(f"message.{col_name}")
        except Exception as e:
            logger.warning(f"Could not migrate message table: {e}")

        if changes:
            db.session.commit()
            logger.info(f"✅ Добавлены колонки: {', '.join(changes)}")
        else:
            logger.info("✅ Все колонки уже существуют")

        # Проверяем существование таблиц
        tables = inspector.get_table_names()
        for table in ['login_history', 'voice_message', 'call', 'report']:
            if table not in tables:
                logger.info(f"➕ Создание таблицы {table}...")
                db.create_all()
                logger.info(f"✅ Таблица {table} создана")

        # Обновляем существующих пользователей
        db.session.execute(text('UPDATE "user" SET is_admin = FALSE WHERE is_admin IS NULL'))
        db.session.execute(text('UPDATE "user" SET two_factor_enabled = FALSE WHERE two_factor_enabled IS NULL'))
        db.session.execute(text('UPDATE "user" SET is_online = FALSE WHERE is_online IS NULL'))
        db.session.commit()

        logger.info("🎉 Миграция базы данных завершена успешно!")

    except Exception as e:
        logger.error(f"❌ Ошибка при миграции: {e}")
        db.session.rollback()


# ──────────────────────────────────────────────────────────────────────────────
#  DB Init & Run
# ──────────────────────────────────────────────────────────────────────────────
def init_app():
    """Initialize application"""
    with app.app_context():
        try:
            # Создаем таблицы (только если их нет)
            db.create_all()
            logger.info("✅ Базовые таблицы созданы")

            # Запускаем миграции
            run_migrations()

            # Создаем папки для загрузок (для видео и аудио)
            ensure_upload_folders()

            # Тест прав на запись
            test_file = os.path.join(app.config['UPLOAD_FOLDER'], 'test.txt')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                logger.info("✅ Временная папка доступна для записи")
            except Exception as e:
                logger.warning(f"⚠️ Временная папка может быть недоступна: {e}")

            # Создаем администратора
            create_admin_user()

            logger.info("🎉 Инициализация приложения завершена!")

        except Exception as e:
            logger.error(f"❌ Ошибка при инициализации: {e}")


if __name__ == "__main__":
    init_app()

    port = int(os.environ.get("PORT", 5000))

    print("\n" + "=" * 70)
    print("🚀 ЗАПУСК KILDEAR SOCIAL NETWORK (DATABASE STORAGE MODE)")
    print("=" * 70)
    print(f"🌐 Сервер запускается на порту: {port}")
    print(f"📁 Временная папка: {app.config['UPLOAD_FOLDER']}")
    print(f"💾 Хранение изображений: В Базе Данных (Data URL)")
    print(f"🐍 Python: {platform.python_version()}")
    print(f"🖥️  Платформа: {platform.system()}")
    print(f"🎯 Режим: {'PRODUCTION' if is_production else 'DEVELOPMENT'}")
    print("=" * 70)
    print("📝 Для остановки нажмите Ctrl+C")
    print("=" * 70 + "\n")

    socketio.run(app,
                 debug=not is_production,
                 host="0.0.0.0",
                 port=port,
                 allow_unsafe_werkzeug=not is_production)