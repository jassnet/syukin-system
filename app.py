#!/usr/bin/env python3
import os
import secrets
import hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from zoneinfo import ZoneInfo

from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

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
# 定期CSV送信設定
CSV_EXPORT_EMAIL = os.getenv("CSV_EXPORT_EMAIL", "").strip()
CSV_EXPORT_SCHEDULE = os.getenv("CSV_EXPORT_SCHEDULE", "")  # 例: "daily" (毎日), "weekly" (毎週月曜), "monthly" (毎月1日), cron形式も可
CSV_EXPORT_DAYS = int(os.getenv("CSV_EXPORT_DAYS", "30"))  # 過去何日分をエクスポートするか

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
    shifts = db.relationship("Shift", backref="user", lazy=True)
    
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
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    clock_in_at = db.Column(db.DateTime(timezone=True), nullable=False)
    clock_out_at = db.Column(db.DateTime(timezone=True), nullable=True)
    clock_in_ip = db.Column(db.String(100))
    clock_in_ua = db.Column(db.String(300))
    clock_out_ip = db.Column(db.String(100))
    clock_out_ua = db.Column(db.String(300))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    breaks = db.relationship("Break", backref="shift", lazy=True, cascade="all, delete-orphan")
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
    shift_id = db.Column(db.Integer, db.ForeignKey("shifts.id"), nullable=False, index=True)
    start_at = db.Column(db.DateTime(timezone=True), nullable=False)
    end_at = db.Column(db.DateTime(timezone=True), nullable=True)
    start_ip = db.Column(db.String(100))
    start_ua = db.Column(db.String(300))
    end_ip = db.Column(db.String(100))
    end_ua = db.Column(db.String(300))

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    user = db.relationship("User", backref="audit_logs")
    action = db.Column(db.String(50), nullable=False)
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer)
    ip = db.Column(db.String(100))
    user_agent = db.Column(db.String(300))
    metadata_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    signature = db.Column(db.String(128))

class SystemConfig(db.Model):
    __tablename__ = "system_configs"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    
    @staticmethod
    def get(key, default=None):
        """設定値を取得（環境変数をフォールバック）"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config and config.value:
            return config.value
        # 環境変数から取得（後方互換性のため）
        return os.getenv(key, default)
    
    @staticmethod
    def set(key, value, user_id=None):
        """設定値を保存"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            config.value = value
            config.updated_at = datetime.now(timezone.utc)
            config.updated_by = user_id
        else:
            config = SystemConfig(key=key, value=value, updated_by=user_id)
            db.session.add(config)
        db.session.commit()
        return config
    
    @staticmethod
    def get_all():
        """全ての設定を辞書形式で取得"""
        configs = SystemConfig.query.all()
        result = {}
        for config in configs:
            result[config.key] = config.value
        return result

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

def log_audit(action, target_type=None, target_id=None, metadata_dict=None):
    try:
        md = json.dumps(metadata_dict or {}, ensure_ascii=False, separators=(",", ":"))
        sig = sign_payload(f"{action}|{target_type}|{target_id}|{md}")
        entry = AuditLog(
            user_id=(current_user.get_id() if current_user.is_authenticated else None),
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip=client_ip(),
            user_agent=user_agent(),
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
def fmt_dt(dt):
    if not dt:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(LOCAL_TZ)
    weekday = WEEKDAY_JA[local.weekday()]
    return f"{local.year}年{local.month:02d}月{local.day:02d}日({weekday}) {local.hour:02d}:{local.minute:02d}:{local.second:02d}"

@app.template_filter("fmt_hms")
def fmt_hms(seconds):
    seconds = int(seconds or 0)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

@app.template_filter("fmt_date_ja")
def fmt_date_ja(value):
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
    return f"{value.year}年{value.month:02d}月{value.day:02d}日({weekday})"

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
    return render_template("dashboard.html", open_shift=open_shift, open_break=open_break, recent=recent)

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
    db.session.add(shift); db.session.commit()
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
    db.session.add(b); db.session.commit()
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
    now_local = datetime.now(LOCAL_TZ)
    default_end = now_local.date(); default_start = default_end - timedelta(days=13)
    try:
        start_date = datetime.fromisoformat(start).date() if start else default_start
        end_date = datetime.fromisoformat(end).date() if end else default_end
    except ValueError:
        abort(400, "日付の形式が不正です。YYYY-MM-DD で指定してください。")
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

    user_candidates = User.query.order_by(User.username.asc()).all()

    return render_template(
        "admin.html",
        shifts=shifts,
        start=start_date.isoformat(),
        end=end_date.isoformat(),
        user_username=user_username,
        daily_totals=daily_totals,
        user_candidates=user_candidates,
    )

def generate_csv(start_date, end_date, user_username=None, user_email=None):
    """CSVデータを生成する共通関数"""
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
    
    csv_data, shift_count = generate_csv(start_date, end_date, user_username if user_username else None, user_email if user_email else None)
    filename = f"attendance_export_{start_date.isoformat()}_{end_date.isoformat()}.csv"
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    log_audit("admin_export", target_type="shift", target_id=None, metadata_dict={"start": start_date.isoformat(), "end": end_date.isoformat(), "email": user_email, "shift_count": shift_count})
    return resp

def send_csv_email(to_email, csv_data, start_date, end_date):
    """CSVファイルをメールで送信"""
    try:
        smtp_host = SystemConfig.get("SMTP_HOST", os.getenv("SMTP_HOST", "localhost"))
        smtp_port = int(SystemConfig.get("SMTP_PORT", os.getenv("SMTP_PORT", "25")))
        smtp_user = SystemConfig.get("SMTP_USER", os.getenv("SMTP_USER", ""))
        smtp_password = SystemConfig.get("SMTP_PASSWORD", os.getenv("SMTP_PASSWORD", ""))
        smtp_use_tls_str = SystemConfig.get("SMTP_USE_TLS", os.getenv("SMTP_USE_TLS", "false"))
        smtp_use_tls = smtp_use_tls_str.lower() in ("true", "1", "yes", "on")
        
        msg = MIMEMultipart()
        smtp_from = SystemConfig.get("SMTP_FROM", os.getenv("SMTP_FROM", smtp_user or "noreply@example.com"))
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = f"出退勤データ CSV - {start_date.isoformat()} ～ {end_date.isoformat()}"
        
        body = f"""出退勤システムからの定期CSVエクスポートです。

期間: {start_date.isoformat()} ～ {end_date.isoformat()}

CSVファイルを添付しています。
"""
        msg.attach(MIMEText(body, "plain", "utf-8"))
        
        filename = f"attendance_export_{start_date.isoformat()}_{end_date.isoformat()}.csv"
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(csv_data)
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(attachment)
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_use_tls:
                server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        app.logger.info(f"CSV email sent to {to_email}")
        return True
    except Exception as e:
        app.logger.exception(f"Failed to send CSV email: {e}")
        return False

def get_csv_export_config():
    """CSVエクスポート設定を取得（DB優先、環境変数フォールバック）"""
    email = SystemConfig.get("CSV_EXPORT_EMAIL", os.getenv("CSV_EXPORT_EMAIL", "").strip())
    schedule = SystemConfig.get("CSV_EXPORT_SCHEDULE", os.getenv("CSV_EXPORT_SCHEDULE", ""))
    days = int(SystemConfig.get("CSV_EXPORT_DAYS", os.getenv("CSV_EXPORT_DAYS", "30")))
    return email, schedule, days

def scheduled_csv_export():
    """定期CSVエクスポートのジョブ関数"""
    with app.app_context():
        email, schedule, days = get_csv_export_config()
        if not email:
            return
        
        now_local = datetime.now(LOCAL_TZ)
        end_date = now_local.date()
        start_date = end_date - timedelta(days=days)
        
        try:
            csv_data, shift_count = generate_csv(start_date, end_date, None, None)
            send_csv_email(email, csv_data, start_date, end_date)
            log_audit("scheduled_csv_export", target_type="system", target_id=None, 
                     metadata_dict={"email": email, "start": start_date.isoformat(), 
                                   "end": end_date.isoformat(), "shift_count": shift_count})
        except Exception as e:
            app.logger.exception(f"Scheduled CSV export failed: {e}")

@app.route("/admin/shift/<int:shift_id>/edit", methods=["GET", "POST"])
@login_required
def admin_shift_edit(shift_id):
    """出退勤データの編集"""
    require_admin()
    ensure_csrf()
    
    shift = Shift.query.get_or_404(shift_id)
    
    if request.method == "POST":
        verify_csrf()
        
        # 変更前の値を保存（監査ログ用）
        old_values = {
            "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
            "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
        }
        
        # 新しい値を取得
        clock_in_str = request.form.get("clock_in_at", "").strip()
        clock_out_str = request.form.get("clock_out_at", "").strip()
        
        try:
            # 日時文字列をパース（datetime-local形式: YYYY-MM-DDTHH:MM または YYYY-MM-DD HH:MM:SS）
            if clock_in_str:
                # datetime-local形式 (YYYY-MM-DDTHH:MM) を処理
                if "T" in clock_in_str:
                    clock_in_local = datetime.strptime(clock_in_str, "%Y-%m-%dT%H:%M")
                else:
                    clock_in_local = datetime.strptime(clock_in_str, "%Y-%m-%d %H:%M:%S")
                shift.clock_in_at = clock_in_local.replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
            else:
                shift.clock_in_at = None
                
            if clock_out_str:
                # datetime-local形式 (YYYY-MM-DDTHH:MM) を処理
                if "T" in clock_out_str:
                    clock_out_local = datetime.strptime(clock_out_str, "%Y-%m-%dT%H:%M")
                else:
                    clock_out_local = datetime.strptime(clock_out_str, "%Y-%m-%d %H:%M:%S")
                shift.clock_out_at = clock_out_local.replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
            else:
                shift.clock_out_at = None
            
            db.session.commit()
            
            # 変更後の値を保存
            new_values = {
                "clock_in_at": shift.clock_in_at.isoformat() if shift.clock_in_at else None,
                "clock_out_at": shift.clock_out_at.isoformat() if shift.clock_out_at else None,
            }
            
            # 監査ログに記録（変更前後の値を含む）
            log_audit("admin_shift_edit", target_type="shift", target_id=shift_id,
                     metadata_dict={
                         "user_username": shift.user.username,
                         "user_email": shift.user.email or "",
                         "old_values": old_values,
                         "new_values": new_values,
                     })
            
            flash("出退勤データを更新しました。", "success")
            return redirect(url_for("admin"))
        except ValueError as e:
            flash(f"日時の形式が不正です: {e}", "error")
        except Exception as e:
            db.session.rollback()
            app.logger.exception(f"Failed to update shift: {e}")
            flash("更新に失敗しました。", "error")
    
    # GETリクエスト時は編集フォームを表示
    clock_in_local = shift.clock_in_at.astimezone(LOCAL_TZ) if shift.clock_in_at else None
    clock_out_local = shift.clock_out_at.astimezone(LOCAL_TZ) if shift.clock_out_at else None
    
    return render_template("shift_edit.html", shift=shift,
                          clock_in_local=clock_in_local, clock_out_local=clock_out_local,
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

@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    """システム設定ページ"""
    require_admin()
    ensure_csrf()
    
    if request.method == "POST":
        verify_csrf()
        
        # CSVエクスポート設定を更新
        csv_email = request.form.get("csv_export_email", "").strip()
        # スケジュール値はselectまたはcron入力から取得
        csv_schedule = request.form.get("csv_export_schedule", "").strip()
        if not csv_schedule:
            # フォールバック: カスタムcron形式が送られてきた場合
            csv_schedule = request.form.get("csv_export_schedule_cron", "").strip()
        csv_days = request.form.get("csv_export_days", "30").strip()
        smtp_host = request.form.get("smtp_host", "").strip()
        smtp_port = request.form.get("smtp_port", "25").strip()
        smtp_user = request.form.get("smtp_user", "").strip()
        smtp_password = request.form.get("smtp_password", "").strip()
        smtp_use_tls = env_bool("smtp_use_tls", False)
        if request.form.get("smtp_use_tls"):
            smtp_use_tls = True
        smtp_from = request.form.get("smtp_from", "").strip()
        
        user_id = current_user.id if current_user.is_authenticated else None
        
        try:
            SystemConfig.set("CSV_EXPORT_EMAIL", csv_email, user_id)
            SystemConfig.set("CSV_EXPORT_SCHEDULE", csv_schedule, user_id)
            SystemConfig.set("CSV_EXPORT_DAYS", csv_days, user_id)
            SystemConfig.set("SMTP_HOST", smtp_host, user_id)
            SystemConfig.set("SMTP_PORT", smtp_port, user_id)
            SystemConfig.set("SMTP_USER", smtp_user, user_id)
            SystemConfig.set("SMTP_PASSWORD", smtp_password, user_id)
            SystemConfig.set("SMTP_USE_TLS", "true" if smtp_use_tls else "false", user_id)
            SystemConfig.set("SMTP_FROM", smtp_from, user_id)
            
            # スケジューラーを更新
            update_scheduler()
            
            # 監査ログに記録
            log_audit("admin_settings_update", target_type="system", target_id=None,
                     metadata_dict={"updated_keys": ["CSV_EXPORT_EMAIL", "CSV_EXPORT_SCHEDULE", "CSV_EXPORT_DAYS", 
                                                     "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_USE_TLS", "SMTP_FROM"]})
            
            flash("設定を保存しました。", "success")
            return redirect(url_for("admin_settings"))
        except Exception as e:
            db.session.rollback()
            app.logger.exception(f"Failed to save settings: {e}")
            flash("設定の保存に失敗しました。", "error")
    
    # GETリクエスト時は設定を表示
    config = SystemConfig.get_all()
    # 環境変数からのフォールバック
    csv_email = config.get("CSV_EXPORT_EMAIL") or os.getenv("CSV_EXPORT_EMAIL", "")
    csv_schedule = config.get("CSV_EXPORT_SCHEDULE") or os.getenv("CSV_EXPORT_SCHEDULE", "")
    csv_days = config.get("CSV_EXPORT_DAYS") or os.getenv("CSV_EXPORT_DAYS", "30")
    smtp_host = config.get("SMTP_HOST") or os.getenv("SMTP_HOST", "localhost")
    smtp_port = config.get("SMTP_PORT") or os.getenv("SMTP_PORT", "25")
    smtp_user = config.get("SMTP_USER") or os.getenv("SMTP_USER", "")
    smtp_password = config.get("SMTP_PASSWORD") or os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls = config.get("SMTP_USE_TLS", os.getenv("SMTP_USE_TLS", "false")).lower() in ("true", "1", "yes", "on")
    smtp_from = config.get("SMTP_FROM") or os.getenv("SMTP_FROM", "")
    
    return render_template("admin_settings.html",
                         csv_email=csv_email,
                         csv_schedule=csv_schedule,
                         csv_days=csv_days,
                         smtp_host=smtp_host,
                         smtp_port=smtp_port,
                         smtp_user=smtp_user,
                         smtp_password=smtp_password,
                         smtp_use_tls=smtp_use_tls,
                         smtp_from=smtp_from)

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
            
            user = User(username=username, name=name or None, email=email or None, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
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
            
            db.session.commit()
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

@app.before_request
def ensure_db():
    db.create_all()

@app.context_processor
def inject_globals():
    return {"current_user": current_user, "is_admin": (current_user.is_authenticated and current_user.is_admin()), "LOCAL_TZ_NAME": str(LOCAL_TZ)}

# グローバルスケジューラー
_scheduler = None

def get_trigger_from_schedule(schedule_str):
    """スケジュール文字列からCronTriggerを生成"""
    from apscheduler.triggers.cron import CronTrigger
    
    schedule_lower = schedule_str.lower().strip()
    
    if schedule_lower == "daily":
        # 毎日 朝9時に実行
        return CronTrigger(hour=9, minute=0, timezone=LOCAL_TZ)
    elif schedule_lower == "weekly":
        # 毎週月曜日 朝9時に実行
        return CronTrigger(day_of_week="mon", hour=9, minute=0, timezone=LOCAL_TZ)
    elif schedule_lower == "monthly":
        # 毎月1日 朝9時に実行
        return CronTrigger(day=1, hour=9, minute=0, timezone=LOCAL_TZ)
    elif " " in schedule_str and schedule_str.count(" ") >= 4:
        # cron形式（例: "0 9 * * *" → 毎日9時）
        try:
            parts = schedule_str.split()
            if len(parts) == 5:
                # CronTriggerのパラメータ: minute, hour, day, month, day_of_week
                return CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4], timezone=LOCAL_TZ)
            else:
                app.logger.warning(f"Invalid cron format: {schedule_str}")
                return None
        except Exception as e:
            app.logger.warning(f"Failed to parse cron schedule: {e}")
            return None
    else:
        app.logger.warning(f"Unknown schedule format: {schedule_str}")
        return None

def update_scheduler():
    """スケジューラーを更新（設定変更時に呼び出し）"""
    global _scheduler
    from apscheduler.schedulers.background import BackgroundScheduler
    
    email, schedule, days = get_csv_export_config()
    
    # 既存のスケジューラーを停止
    if _scheduler:
        try:
            _scheduler.shutdown(wait=False)
        except:
            pass
        _scheduler = None
    
    # 設定がない場合はスケジューラーを起動しない
    if not email or not schedule:
        app.logger.info("CSV export scheduler disabled (email or schedule not set)")
        return
    
    # 新しいスケジューラーを起動
    try:
        trigger = get_trigger_from_schedule(schedule)
        if not trigger:
            return
        
        _scheduler = BackgroundScheduler()
        _scheduler.add_job(func=scheduled_csv_export, trigger=trigger, id="csv_export_job", replace_existing=True)
        _scheduler.start()
        app.logger.info(f"Scheduled CSV export updated: {schedule} -> {email}")
    except Exception as e:
        app.logger.exception(f"Failed to update scheduler: {e}")

def init_scheduler():
    """スケジューラーを初期化（起動時）"""
    update_scheduler()

# アプリ起動時にスケジューラーを初期化
try:
    init_scheduler()
except Exception as e:
    app.logger.exception(f"Failed to initialize scheduler: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
