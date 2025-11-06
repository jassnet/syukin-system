#!/usr/bin/env python3
import os
import secrets
import hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from zoneinfo import ZoneInfo
import click

from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, make_response, jsonify, has_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

def env_bool(name, default=False):
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)

# ---------- DB: default to SQLite for local simplicity; prod should set DATABASE_URL to PostgreSQL ----------
DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///attendance.db"
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_bool("SESSION_COOKIE_SECURE", False)

LOCAL_TZ = ZoneInfo(os.getenv("TIMEZONE", "Asia/Tokyo"))
# CSVエクスポート期間の上限（管理画面・手動エクスポート共通）
CSV_EXPORT_MAX_DAYS = max(1, int(os.getenv("CSV_EXPORT_MAX_DAYS", "365")))

db = SQLAlchemy(app)

WEEKDAY_JA = ["月", "火", "水", "木", "金", "土", "日"]

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=True, index=True)
    name = db.Column(db.String(200))
    picture = db.Column(db.String(500))
    role = db.Column(db.String(20), default="user")
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime(timezone=True))
    shifts = db.relationship(
        "Shift",
        backref=db.backref("user", lazy=True),
        lazy=True,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    
    def set_password(self, password):
        """パスワードをハッシュ化して設定"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """パスワードを検証"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == "admin"

class Shift(db.Model):
    __tablename__ = "shifts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    clock_in_at = db.Column(db.DateTime(timezone=True), nullable=False)
    clock_out_at = db.Column(db.DateTime(timezone=True), nullable=True)
    clock_in_ip = db.Column(db.String(100))
    clock_in_ua = db.Column(db.String(300))
    clock_out_ip = db.Column(db.String(100))
    clock_out_ua = db.Column(db.String(300))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    breaks = db.relationship("Break", backref="shift", lazy=True, cascade="all, delete-orphan", passive_deletes=True)
    __table_args__ = (
        db.Index(
            "ix_shifts_user_open_unique",
            "user_id",
            unique=True,
            sqlite_where=(clock_out_at.is_(None)),
            postgresql_where=(clock_out_at.is_(None)),
        ),
    )
    @property
    def is_open(self):
        return self.clock_out_at is None
    def total_break_seconds(self, now=None):
        if now is None:
            now = datetime.now(timezone.utc)
        now = ensure_aware(now)
        total = 0
        for b in self.breaks:
            start = ensure_aware(b.start_at)
            end = ensure_aware(b.end_at) if b.end_at else now
            total += max(0, int((end - start).total_seconds()))
        return total
    def worked_seconds(self, now=None):
        if now is None:
            now = datetime.now(timezone.utc)
        start = ensure_aware(self.clock_in_at)
        end = ensure_aware(self.clock_out_at) if self.clock_out_at else ensure_aware(now)
        total = max(0, int((end - start).total_seconds()))
        total -= self.total_break_seconds(now=now)
        return max(0, total)

class Break(db.Model):
    __tablename__ = "breaks"
    id = db.Column(db.Integer, primary_key=True)
    shift_id = db.Column(db.Integer, db.ForeignKey("shifts.id", ondelete="CASCADE"), nullable=False, index=True)
    start_at = db.Column(db.DateTime(timezone=True), nullable=False)
    end_at = db.Column(db.DateTime(timezone=True), nullable=True)
    start_ip = db.Column(db.String(100))
    start_ua = db.Column(db.String(300))
    end_ip = db.Column(db.String(100))
    end_ua = db.Column(db.String(300))
    __table_args__ = (
        db.Index(
            "ix_breaks_shift_open_unique",
            "shift_id",
            unique=True,
            sqlite_where=(end_at.is_(None)),
            postgresql_where=(end_at.is_(None)),
        ),
    )

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    user = db.relationship("User", backref="audit_logs")
    action = db.Column(db.String(50), nullable=False)
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer)
    ip = db.Column(db.String(100))
    user_agent = db.Column(db.String(300))
    metadata_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    signature = db.Column(db.String(128))

def client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"

def user_agent():
    return request.headers.get("User-Agent", "?")[:300]

def sign_payload(payload: str) -> str:
    key = (app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

def ensure_aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def ensure_valid_range(start_date, end_date):
    """開始・終了日の妥当性を検証（最大期間もチェック）"""
    if start_date > end_date:
        raise ValueError("終了日は開始日以降を指定してください。")
    span_days = (end_date - start_date).days + 1
    if span_days > CSV_EXPORT_MAX_DAYS:
        raise ValueError(f"期間は最大{CSV_EXPORT_MAX_DAYS}日までにしてください。")
    return start_date, end_date

def parse_local_datetime(value, field_label="日時"):
    """datetime-localなどから受け取ったローカル時刻文字列をUTCに変換"""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    formats = ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S")
    last_error = None
    for fmt in formats:
        try:
            local_dt = datetime.strptime(value, fmt)
            return local_dt.replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
        except ValueError as e:
            last_error = e
    raise ValueError(f"{field_label}の形式が不正です: {value}") from last_error

def format_local_form_value(dt):
    """datetime-local入力用の文字列を生成"""
    dt = ensure_aware(dt)
    if not dt:
        return ""
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M")

def admin_redirect_with_filters():
    """管理画面のフィルタ値を維持したままリダイレクト"""
    params = {}
    for key in ("start", "end", "username"):
        value = request.form.get(key, "").strip()
        if value:
            params[key] = value
    return redirect(url_for("admin", **params))

def log_audit(action, target_type=None, target_id=None, metadata_dict=None, *, user_id=None, ip=None, user_agent_str=None):
    try:
        md = json.dumps(metadata_dict or {}, ensure_ascii=False, separators=(",", ":"))
        sig = sign_payload(f"{action}|{target_type}|{target_id}|{md}")
        if has_request_context():
            derived_user_id = current_user.get_id() if current_user.is_authenticated else None
            derived_ip = client_ip()
            derived_ua = user_agent()
        else:
            derived_user_id = None
            derived_ip = None
            derived_ua = None
        entry = AuditLog(
            user_id=user_id if user_id is not None else derived_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip=ip if ip is not None else derived_ip,
            user_agent=user_agent_str if user_agent_str is not None else derived_ua,
            metadata_json=md,
            signature=sig,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        app.logger.exception("Audit log failed: %s", e)

def ensure_csrf():
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok

def verify_csrf():
    form_tok = request.form.get("csrf_token", "")
    ok = form_tok and session.get("csrf_token") and secrets.compare_digest(form_tok, session["csrf_token"])
    if not ok:
        abort(400, "CSRF token missing or invalid")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter("fmt_dt")
def fmt_dt(dt, full=False):
    if not dt:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(LOCAL_TZ)
    weekday = WEEKDAY_JA[local.weekday()]
    if full:
        return f"{local.year}年{local.month:02d}月{local.day:02d}日({weekday}) {local.hour:02d}:{local.minute:02d}:{local.second:02d}"
    return f"{local.month:02d}月{local.day:02d}日({weekday}) {local.hour:02d}:{local.minute:02d}"

@app.template_filter("fmt_hms")
def fmt_hms(seconds, precise=False):
    seconds = int(seconds or 0)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if precise:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}"

@app.template_filter("fmt_date_ja")
def fmt_date_ja(value, full=False):
    if not value:
        return "-"
    if isinstance(value, datetime):
        value = ensure_aware(value).astimezone(LOCAL_TZ).date()
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            value = ensure_aware(parsed).astimezone(LOCAL_TZ).date()
        except ValueError:
            return value
    weekday = WEEKDAY_JA[value.weekday()]
    if full:
        return f"{value.year}年{value.month:02d}月{value.day:02d}日({weekday})"
    return f"{value.month:02d}月{value.day:02d}日({weekday})"

@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_csrf()
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("ユーザーIDとパスワードを入力してください。", "error")
            return redirect(url_for("login"))
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()
            login_user(user)
            log_audit("login", target_type="user", target_id=user.id, metadata_dict={"username": username})
            flash("ログインしました。", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("ユーザーIDまたはパスワードが正しくありません。", "error")
            return redirect(url_for("login"))
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_audit("logout", target_type="user", target_id=current_user.id)
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    ensure_csrf()
    open_shift = Shift.query.filter_by(user_id=current_user.id, clock_out_at=None).order_by(Shift.id.desc()).first()
    open_break = None
    if open_shift:
        open_break = Break.query.filter_by(shift_id=open_shift.id, end_at=None).order_by(Break.id.desc()).first()
    recent = Shift.query.filter_by(user_id=current_user.id).order_by(Shift.clock_in_at.desc()).limit(10).all()
    admin_overview = None
    if current_user.is_admin():
        try:
            admin_overview = build_admin_overview(None, None, "")
        except ValueError as e:
            flash(str(e), "error")
    return render_template("dashboard.html", open_shift=open_shift, open_break=open_break, recent=recent, admin_overview=admin_overview)

def _get_open_shift_or_abort(user_id):
    s = Shift.query.filter_by(user_id=user_id, clock_out_at=None).order_by(Shift.id.desc()).first()
    if not s:
        abort(400, "現在、出勤中の記録はありません。")
    return s

def _get_open_break_or_abort(shift_id):
    b = Break.query.filter_by(shift_id=shift_id, end_at=None).order_by(Break.id.desc()).first()
    if not b:
        abort(400, "現在、休憩中の記録はありません。")
    return b

@app.route("/clock/in", methods=["POST"])
@login_required
def clock_in():
    verify_csrf()
    open_shift = Shift.query.filter_by(user_id=current_user.id, clock_out_at=None).first()
    if open_shift:
        abort(400, "すでに出勤中です。先に退勤してください。")
    now = datetime.now(timezone.utc)
    shift = Shift(user_id=current_user.id, clock_in_at=now, clock_in_ip=client_ip(), clock_in_ua=user_agent())
    db.session.add(shift)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        abort(400, "別の端末から既に出勤が記録されました。画面を更新して確認してください。")
    log_audit("clock_in", target_type="shift", target_id=shift.id, metadata_dict={"at": shift.clock_in_at.isoformat()})
    flash("出勤を記録しました。", "success")
    return redirect(url_for("dashboard"))

@app.route("/clock/out", methods=["POST"])
@login_required
def clock_out():
    verify_csrf()
    shift = _get_open_shift_or_abort(current_user.id)
    now = datetime.now(timezone.utc)
    open_break = Break.query.filter_by(shift_id=shift.id, end_at=None).first()
    if open_break:
        open_break.end_at = now; open_break.end_ip = client_ip(); open_break.end_ua = user_agent(); db.session.add(open_break)
    shift.clock_out_at = now; shift.clock_out_ip = client_ip(); shift.clock_out_ua = user_agent(); db.session.add(shift)
    db.session.commit()
    log_audit("clock_out", target_type="shift", target_id=shift.id, metadata_dict={"at": shift.clock_out_at.isoformat()})
    flash("退勤を記録しました。", "success")
    return redirect(url_for("dashboard"))

@app.route("/break/start", methods=["POST"])
@login_required
def break_start():
    verify_csrf()
    shift = _get_open_shift_or_abort(current_user.id)
    existing = Break.query.filter_by(shift_id=shift.id, end_at=None).first()
    if existing:
        abort(400, "既に休憩中です。先に休憩終了をしてください。")
    now = datetime.now(timezone.utc)
    b = Break(shift_id=shift.id, start_at=now, start_ip=client_ip(), start_ua=user_agent())
    db.session.add(b)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        abort(400, "他端末から休憩開始済みです。画面を更新して再確認してください。")
    log_audit("break_start", target_type="break", target_id=b.id, metadata_dict={"at": b.start_at.isoformat(), "shift_id": shift.id})
    flash("休憩開始を記録しました。", "success")
    return redirect(url_for("dashboard"))

@app.route("/break/end", methods=["POST"])
@login_required
def break_end():
    verify_csrf()
    shift = _get_open_shift_or_abort(current_user.id)
    b = _get_open_break_or_abort(shift.id)
    now = datetime.now(timezone.utc)
    b.end_at = now; b.end_ip = client_ip(); b.end_ua = user_agent(); db.session.add(b)
    db.session.commit()
    log_audit("break_end", target_type="break", target_id=b.id, metadata_dict={"at": b.end_at.isoformat(), "shift_id": shift.id})
    flash("休憩終了を記録しました。", "success")
    return redirect(url_for("dashboard"))

def require_admin():
    if not (current_user.is_authenticated and current_user.is_admin()):
        abort(403, "管理者のみアクセス可能です。")

@app.route("/admin")
@login_required
def admin():
    require_admin()
    ensure_csrf()
    start = request.args.get("start"); end = request.args.get("end"); user_username = request.args.get("username", "").strip()
    try:
        context = build_admin_overview(start, end, user_username, include_candidates=True)
    except ValueError as e:
        abort(400, str(e))

    return render_template(
        "admin.html",
        **context,
    )

@app.route("/admin/shift/create", methods=["POST"])
@login_required
def admin_shift_create():
    require_admin()
    verify_csrf()
    try:
        user_id = request.form.get("user_id")
        if not user_id:
            raise ValueError("ユーザーを選択してください。")
        user = User.query.get(user_id)
        if not user:
            raise ValueError("指定されたユーザーが見つかりません。")
        clock_in_at = parse_local_datetime(request.form.get("clock_in_at"), "出勤時刻")
        if not clock_in_at:
            raise ValueError("出勤時刻を入力してください。")
        clock_out_at = parse_local_datetime(request.form.get("clock_out_at"), "退勤時刻")
        if clock_out_at and clock_out_at < clock_in_at:
            raise ValueError("退勤時刻は出勤時刻以降を指定してください。")
        shift = Shift(
            user_id=user.id,
            clock_in_at=clock_in_at,
            clock_out_at=clock_out_at,
            clock_in_ip=client_ip(),
            clock_in_ua=user_agent(),
            clock_out_ip=client_ip() if clock_out_at else None,
            clock_out_ua=user_agent() if clock_out_at else None,
        )
        db.session.add(shift)
        db.session.commit()
        log_audit(
            "admin_shift_create",
            target_type="shift",
            target_id=shift.id,
            metadata_dict={
                "user_username": user.username,
                "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
                "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
            },
        )
        flash("出退勤記録を追加しました。", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to create shift: %s", e)
        flash("出退勤記録の追加に失敗しました。", "error")
    return admin_redirect_with_filters()

@app.route("/admin/shift/<int:shift_id>/delete", methods=["POST"])
@login_required
def admin_shift_delete(shift_id):
    require_admin()
    verify_csrf()
    shift = Shift.query.get_or_404(shift_id)
    metadata = {
        "user_username": shift.user.username if shift.user else None,
        "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
        "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
        "break_count": len(shift.breaks),
        "worked_seconds": shift.worked_seconds(),
    }
    try:
        db.session.delete(shift)
        db.session.commit()
        log_audit("admin_shift_delete", target_type="shift", target_id=shift_id, metadata_dict=metadata)
        flash("出退勤記録を削除しました。", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to delete shift: %s", e)
        flash("出退勤記録の削除に失敗しました。", "error")
    return admin_redirect_with_filters()

def generate_csv(start_date, end_date, user_username=None, user_email=None):
    """CSVデータを生成する共通関数"""
    start_date, end_date = ensure_valid_range(start_date, end_date)
    start_utc = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    end_utc = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    
    q = Shift.query.join(User).filter(Shift.clock_in_at >= start_utc, Shift.clock_in_at <= end_utc)
    if user_username:
        q = q.filter(User.username == user_username)
    elif user_email:
        q = q.filter(User.email == user_email)
    shifts = q.order_by(Shift.clock_in_at.asc()).all()
    
    import csv
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["user_username","user_email","user_name","shift_id","clock_in_local","clock_out_local","worked_seconds","worked_hms","clock_in_utc","clock_out_utc","clock_in_ip","clock_out_ip","clock_in_ua","clock_out_ua","break_count","breaks_total_seconds","breaks_total_hms"])
    for s in shifts:
        in_local = s.clock_in_at.astimezone(LOCAL_TZ) if s.clock_in_at else None
        out_local = s.clock_out_at.astimezone(LOCAL_TZ) if s.clock_out_at else None
        worked = s.worked_seconds(); brk_sec = s.total_break_seconds()
        writer.writerow([
            s.user.username, s.user.email or "", s.user.name or "", s.id,
            in_local.strftime("%Y-%m-%d %H:%M:%S") if in_local else "",
            out_local.strftime("%Y-%m-%d %H:%M:%S") if out_local else "",
            worked, f"{worked//3600:02d}:{(worked%3600)//60:02d}:{worked%60:02d}",
            s.clock_in_at.isoformat() if s.clock_in_at else "",
            s.clock_out_at.isoformat() if s.clock_out_at else "",
            s.clock_in_ip or "", s.clock_out_ip or "", s.clock_in_ua or "", s.clock_out_ua or "",
            len(s.breaks), brk_sec, f"{brk_sec//3600:02d}:{(brk_sec%3600)//60:02d}:{brk_sec%60:02d}",
        ])
    return buf.getvalue().encode("utf-8-sig"), len(shifts)

def build_admin_overview(start_arg=None, end_arg=None, user_username="", include_candidates=False):
    now_local = datetime.now(LOCAL_TZ)
    default_end = now_local.date()
    default_start = default_end - timedelta(days=13)

    try:
        start_date = datetime.fromisoformat(start_arg).date() if start_arg else default_start
        end_date = datetime.fromisoformat(end_arg).date() if end_arg else default_end
    except ValueError:
        abort(400, "日付の形式が不正です。YYYY-MM-DD で指定してください。")

    start_date, end_date = ensure_valid_range(start_date, end_date)
    start_utc = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    end_utc = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)

    q = Shift.query.join(User).filter(Shift.clock_in_at >= start_utc, Shift.clock_in_at <= end_utc)
    if user_username:
        q = q.filter(User.username == user_username)
    shifts = q.order_by(Shift.clock_in_at.desc()).all()

    daily_buckets = defaultdict(lambda: {"seconds": 0, "count": 0})
    for s in shifts:
        if not s.clock_in_at:
            continue
        local_date = s.clock_in_at.astimezone(LOCAL_TZ).date()
        bucket = daily_buckets[local_date]
        bucket["seconds"] += s.worked_seconds()
        bucket["count"] += 1

    daily_totals = [
        {
            "date": date_key,
            "seconds": bucket["seconds"],
            "worked_hms": fmt_hms(bucket["seconds"]),
            "count": bucket["count"],
        }
        for date_key, bucket in sorted(daily_buckets.items(), reverse=True)
    ]

    context = {
        "shifts": shifts,
        "start": start_date.isoformat(),
        "end": end_date.isoformat(),
        "user_username": user_username,
        "daily_totals": daily_totals,
    }
    if include_candidates:
        context["user_candidates"] = User.query.order_by(User.username.asc()).all()
    return context

@app.route("/admin/export")
@login_required
def admin_export():
    require_admin()
    start = request.args.get("start"); end = request.args.get("end"); user_email = request.args.get("email", "").strip().lower()
    user_username = request.args.get("username", "").strip()
    now_local = datetime.now(LOCAL_TZ)
    default_end = now_local.date(); default_start = default_end - timedelta(days=13)
    try:
        start_date = datetime.fromisoformat(start).date() if start else default_start
        end_date = datetime.fromisoformat(end).date() if end else default_end
    except ValueError:
        abort(400, "日付の形式が不正です。YYYY-MM-DD で指定してください。")
    try:
        start_date, end_date = ensure_valid_range(start_date, end_date)
    except ValueError as e:
        abort(400, str(e))

    csv_data, shift_count = generate_csv(start_date, end_date, user_username if user_username else None, user_email if user_email else None)
    filename = f"attendance_export_{start_date.isoformat()}_{end_date.isoformat()}.csv"
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    log_audit("admin_export", target_type="shift", target_id=None, metadata_dict={"start": start_date.isoformat(), "end": end_date.isoformat(), "email": user_email, "shift_count": shift_count})
    return resp

@app.route("/admin/shift/<int:shift_id>/edit", methods=["GET", "POST"])
@login_required
def admin_shift_edit(shift_id):
    """出退勤データの編集"""
    require_admin()
    ensure_csrf()
    
    shift = Shift.query.get_or_404(shift_id)
    
    if request.method == "POST":
        verify_csrf()
        action = request.form.get("action", "update_shift")
        
        try:
            if action == "update_shift":
                old_values = {
                    "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
                    "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
                }

                clock_in_at = parse_local_datetime(request.form.get("clock_in_at"), "出勤時刻")
                if not clock_in_at:
                    raise ValueError("出勤時刻を入力してください。")
                clock_out_at = parse_local_datetime(request.form.get("clock_out_at"), "退勤時刻")
                if clock_out_at and clock_out_at < clock_in_at:
                    raise ValueError("退勤時刻は出勤時刻以降を指定してください。")

                shift.clock_in_at = clock_in_at
                shift.clock_out_at = clock_out_at
                
                db.session.commit()
                
                new_values = {
                    "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
                    "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
                }
                
                log_audit("admin_shift_edit", target_type="shift", target_id=shift_id,
                         metadata_dict={
                             "user_username": shift.user.username,
                             "user_email": shift.user.email or "",
                             "old_values": old_values,
                             "new_values": new_values,
                         })
                flash("出退勤データを更新しました。", "success")
                return redirect(url_for("admin"))
            
            elif action == "break_add":
                start_at = parse_local_datetime(request.form.get("start_at"), "休憩開始時刻")
                end_at = parse_local_datetime(request.form.get("end_at"), "休憩終了時刻")
                if not start_at:
                    raise ValueError("休憩開始時刻を入力してください。")
                if end_at and end_at < start_at:
                    raise ValueError("休憩終了時刻は開始時刻以降を指定してください。")
                new_break = Break(shift_id=shift.id, start_at=start_at, end_at=end_at)
                db.session.add(new_break)
                db.session.commit()
                log_audit("admin_break_add", target_type="break", target_id=new_break.id,
                         metadata_dict={
                             "shift_id": shift.id,
                             "start_at": new_break.start_at.isoformat() if new_break.start_at else None,
                             "end_at": new_break.end_at.isoformat() if new_break.end_at else None,
                         })
                flash("休憩を追加しました。", "success")
                return redirect(url_for("admin_shift_edit", shift_id=shift_id))
            
            elif action == "break_update":
                break_id = int(request.form.get("break_id", "0"))
                target_break = Break.query.filter_by(id=break_id, shift_id=shift_id).first()
                if not target_break:
                    abort(404, "指定された休憩が見つかりません。")
                old_values = {
                    "start_at": target_break.start_at.isoformat() if target_break.start_at else None,
                    "end_at": target_break.end_at.isoformat() if target_break.end_at else None,
                }
                start_at = parse_local_datetime(request.form.get("start_at"), "休憩開始時刻")
                end_at = parse_local_datetime(request.form.get("end_at"), "休憩終了時刻")
                if not start_at:
                    raise ValueError("休憩開始時刻を入力してください。")
                if end_at and end_at < start_at:
                    raise ValueError("休憩終了時刻は開始時刻以降を指定してください。")
                target_break.start_at = start_at
                target_break.end_at = end_at
                db.session.commit()
                new_values = {
                    "start_at": target_break.start_at.isoformat() if target_break.start_at else None,
                    "end_at": target_break.end_at.isoformat() if target_break.end_at else None,
                }
                log_audit("admin_break_update", target_type="break", target_id=target_break.id,
                         metadata_dict={
                             "shift_id": shift.id,
                             "old_values": old_values,
                             "new_values": new_values,
                         })
                flash("休憩を更新しました。", "success")
                return redirect(url_for("admin_shift_edit", shift_id=shift_id))
            
            elif action == "break_delete":
                break_id = int(request.form.get("break_id", "0"))
                target_break = Break.query.filter_by(id=break_id, shift_id=shift_id).first()
                if not target_break:
                    abort(404, "指定された休憩が見つかりません。")
                metadata = {
                    "shift_id": shift.id,
                    "start_at": target_break.start_at.isoformat() if target_break.start_at else None,
                    "end_at": target_break.end_at.isoformat() if target_break.end_at else None,
                }
                db.session.delete(target_break)
                db.session.commit()
                log_audit("admin_break_delete", target_type="break", target_id=break_id,
                         metadata_dict=metadata)
                flash("休憩を削除しました。", "success")
                return redirect(url_for("admin_shift_edit", shift_id=shift_id))
            
            elif action == "break_reset":
                deleted_ids = [b.id for b in shift.breaks]
                for b in list(shift.breaks):
                    db.session.delete(b)
                db.session.commit()
                log_audit("admin_break_reset", target_type="shift", target_id=shift_id,
                         metadata_dict={"deleted_break_ids": deleted_ids})
                flash("休憩をリセットしました。", "success")
                return redirect(url_for("admin_shift_edit", shift_id=shift_id))
            
            else:
                flash("不正な操作です。", "error")
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            db.session.rollback()
            app.logger.exception(f"Failed to update shift: {e}")
            flash("更新に失敗しました。", "error")
    
    clock_in_form = format_local_form_value(shift.clock_in_at)
    clock_out_form = format_local_form_value(shift.clock_out_at)
    
    break_entries = []
    ordered_breaks = sorted(shift.breaks, key=lambda b: (b.start_at or datetime.min.replace(tzinfo=timezone.utc)))
    for br in ordered_breaks:
        break_entries.append({
            "id": br.id,
            "start_form": format_local_form_value(br.start_at),
            "end_form": format_local_form_value(br.end_at),
            "start_utc": br.start_at.isoformat() if br.start_at else None,
            "end_utc": br.end_at.isoformat() if br.end_at else None,
            "is_open": br.end_at is None,
        })
    
    return render_template("shift_edit.html", shift=shift,
                          clock_in_form=clock_in_form, clock_out_form=clock_out_form,
                          break_entries=break_entries,
                          LOCAL_TZ_NAME=str(LOCAL_TZ))

@app.route("/admin/shift/<int:shift_id>", methods=["GET"])
@login_required
def admin_shift_detail(shift_id):
    """出退勤データの詳細（JSON API）"""
    require_admin()
    shift = Shift.query.get_or_404(shift_id)
    
    clock_in_local = shift.clock_in_at.astimezone(LOCAL_TZ) if shift.clock_in_at else None
    clock_out_local = shift.clock_out_at.astimezone(LOCAL_TZ) if shift.clock_out_at else None
    
    return jsonify({
        "id": shift.id,
        "user_username": shift.user.username,
        "user_email": shift.user.email or "",
        "user_name": shift.user.name or "",
        "clock_in_at": clock_in_local.strftime("%Y-%m-%d %H:%M:%S") if clock_in_local else None,
        "clock_out_at": clock_out_local.strftime("%Y-%m-%d %H:%M:%S") if clock_out_local else None,
        "clock_in_form": clock_in_local.strftime("%Y-%m-%dT%H:%M") if clock_in_local else "",
        "clock_out_form": clock_out_local.strftime("%Y-%m-%dT%H:%M") if clock_out_local else "",
        "clock_in_utc": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
        "clock_out_utc": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
        "clock_in_ip": shift.clock_in_ip,
        "clock_out_ip": shift.clock_out_ip,
        "worked_seconds": shift.worked_seconds(),
        "worked_hms": fmt_hms(shift.worked_seconds()),
        "break_count": len(shift.breaks),
        "break_seconds": shift.total_break_seconds(),
        "break_hms": fmt_hms(shift.total_break_seconds()),
    })

def _parse_audit_filters(max_limit=500, default_limit=200):
    action = request.args.get("action", "").strip()
    username = request.args.get("username", "").strip()
    try:
        limit = int(request.args.get("limit", str(default_limit)))
    except ValueError:
        limit = default_limit
    limit = max(1, min(limit, max_limit))
    return action, username, limit

def _audit_log_query(action, username):
    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    if username:
        query = query.join(User).filter(User.username == username)
    return query

@app.route("/admin/audit")
@login_required
def admin_audit():
    """監査ログの閲覧"""
    require_admin()
    ensure_csrf()

    action, username, limit = _parse_audit_filters()
    query = _audit_log_query(action, username)
    logs = query.limit(limit).all()
    action_rows = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action.asc()).all()
    action_choices = [row[0] for row in action_rows]
    user_candidates = User.query.order_by(User.username.asc()).all()

    log_entries = []
    for log in logs:
        try:
            metadata = json.loads(log.metadata_json) if log.metadata_json else {}
        except Exception:
            metadata = {"raw": log.metadata_json}
        log_entries.append({"log": log, "metadata": metadata})

    return render_template(
        "admin_audit.html",
        log_entries=log_entries,
        action_choices=action_choices,
        selected_action=action,
        selected_username=username,
        limit=limit,
        user_candidates=user_candidates,
    )

@app.route("/admin/audit/export")
@login_required
def admin_audit_export():
    """監査ログのCSVエクスポート"""
    require_admin()
    action, username, limit = _parse_audit_filters(max_limit=5000, default_limit=1000)
    query = _audit_log_query(action, username)
    logs = query.limit(limit).all()

    import csv
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "created_at_local",
        "created_at_utc",
        "action",
        "user_username",
        "user_email",
        "user_name",
        "target_type",
        "target_id",
        "ip",
        "user_agent",
        "metadata_json",
        "signature",
    ])

    for log in logs:
        local_ts = log.created_at.astimezone(LOCAL_TZ) if log.created_at else None
        created_local = local_ts.strftime("%Y-%m-%d %H:%M:%S") if local_ts else ""
        created_utc = log.created_at.isoformat() if log.created_at else ""
        try:
            metadata = json.loads(log.metadata_json) if log.metadata_json else {}
        except Exception:
            metadata = {"raw": log.metadata_json}
        metadata_str = json.dumps(metadata, ensure_ascii=False, separators=(",", ":")) if metadata else ""
        writer.writerow([
            created_local,
            created_utc,
            log.action,
            log.user.username if log.user else "",
            log.user.email if log.user else "",
            log.user.name if log.user else "",
            log.target_type or "",
            log.target_id or "",
            log.ip or "",
            log.user_agent or "",
            metadata_str,
            log.signature or "",
        ])

    csv_data = buf.getvalue().encode("utf-8-sig")
    filename = f"audit_export_{datetime.now(LOCAL_TZ).strftime('%Y%m%d_%H%M%S')}.csv"
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"

    log_audit(
        "admin_audit_export",
        target_type="audit_log",
        target_id=None,
        metadata_dict={
            "action": action or None,
            "username": username or None,
            "limit": limit,
            "count": len(logs),
        },
    )

    return resp

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    """ユーザー管理ページ"""
    require_admin()
    ensure_csrf()
    
    if request.method == "POST":
        verify_csrf()
        action = request.form.get("action")
        
        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            role = request.form.get("role", "user")
            
            if not username or not password:
                flash("ユーザーIDとパスワードは必須です。", "error")
                return redirect(url_for("admin_users"))
            
            if User.query.filter_by(username=username).first():
                flash("このユーザーIDは既に使用されています。", "error")
                return redirect(url_for("admin_users"))
            if email and User.query.filter_by(email=email).first():
                flash("このメールアドレスは既に使用されています。", "error")
                return redirect(url_for("admin_users"))
            
            user = User(username=username, name=name or None, email=email or None, role=role)
            user.set_password(password)
            try:
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("ユーザーの作成中にエラーが発生しました。入力内容を確認してください。", "error")
                return redirect(url_for("admin_users"))
            log_audit("admin_user_create", target_type="user", target_id=user.id, 
                     metadata_dict={"username": username, "role": role})
            flash("ユーザーを作成しました。", "success")
            return redirect(url_for("admin_users"))
        
        elif action == "update":
            user_id = request.form.get("user_id")
            user = User.query.get_or_404(user_id)
            
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            role = request.form.get("role", "user")
            password = request.form.get("password", "").strip()
            
            user.name = name or None
            user.email = email or None
            user.role = role
            
            if password:
                user.set_password(password)
            
            if email:
                existing = User.query.filter(User.email == email, User.id != user.id).first()
                if existing:
                    flash("このメールアドレスは既に使用されています。", "error")
                    return redirect(url_for("admin_users"))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("ユーザーの更新に失敗しました。入力内容を確認してください。", "error")
                return redirect(url_for("admin_users"))
            log_audit("admin_user_update", target_type="user", target_id=user.id,
                     metadata_dict={"username": user.username, "role": role, "password_changed": bool(password)})
            flash("ユーザーを更新しました。", "success")
            return redirect(url_for("admin_users"))
        
        elif action == "delete":
            user_id = request.form.get("user_id")
            user = User.query.get_or_404(user_id)
            
            if user.id == current_user.id:
                flash("自分自身を削除することはできません。", "error")
                return redirect(url_for("admin_users"))
            
            username = user.username
            AuditLog.query.filter_by(user_id=user.id).update({"user_id": None})
            db.session.delete(user)
            db.session.commit()
            log_audit("admin_user_delete", target_type="user", target_id=user_id,
                     metadata_dict={"username": username})
            flash("ユーザーを削除しました。", "success")
            return redirect(url_for("admin_users"))
    
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_users.html", users=users)

@app.route("/healthz")
def healthz():
    return "ok"

@app.context_processor
def inject_globals():
    return {"current_user": current_user, "is_admin": (current_user.is_authenticated and current_user.is_admin()), "LOCAL_TZ_NAME": str(LOCAL_TZ)}

@app.cli.command("init-db")
def init_db_command():
    """Create all database tables."""
    db.create_all()
    click.echo("Initialized the database.")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
