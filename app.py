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
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
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
ADMIN_EMAILS = set([e.strip().lower() for e in (os.getenv("ADMIN_EMAILS") or "").split(",") if e.strip()])
ALLOW_DEV_LOGIN = env_bool("ALLOW_DEV_LOGIN", False)
# 定期CSV送信設定
CSV_EXPORT_EMAIL = os.getenv("CSV_EXPORT_EMAIL", "").strip()
CSV_EXPORT_SCHEDULE = os.getenv("CSV_EXPORT_SCHEDULE", "")  # 例: "daily" (毎日), "weekly" (毎週月曜), "monthly" (毎月1日), cron形式も可
CSV_EXPORT_DAYS = int(os.getenv("CSV_EXPORT_DAYS", "30"))  # 過去何日分をエクスポートするか

db = SQLAlchemy(app)

WEEKDAY_JA = ["月", "火", "水", "木", "金", "土", "日"]

login_manager = LoginManager(app)
login_manager.login_view = "login"

oauth = OAuth(app)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    client_kwargs={"scope": "openid email profile"},
)

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200))
    picture = db.Column(db.String(500))
    role = db.Column(db.String(20), default="user")
    google_sub = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime(timezone=True))
    shifts = db.relationship("Shift", backref="user", lazy=True)
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

@app.route("/login")
def login():
    ensure_csrf()
    return render_template("login.html", allow_dev_login=ALLOW_DEV_LOGIN)

@app.route("/auth/google")
def auth_google():
    redirect_uri = os.getenv("OAUTH_REDIRECT_URI") or url_for("auth_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    token = oauth.google.authorize_access_token()
    userinfo_endpoint = oauth.google.server_metadata.get(
        "userinfo_endpoint", "https://openidconnect.googleapis.com/v1/userinfo"
    )
    resp = oauth.google.get(userinfo_endpoint)
    if resp.status_code != 200:
        abort(400, "Failed to fetch user info from Google")
    info = resp.json()
    email = (info.get("email") or "").lower()
    if not email:
        abort(400, "Email not returned by Google")
    sub = info.get("sub")
    name = info.get("name") or email
    picture = info.get("picture")
    user = User.query.filter_by(email=email).first()
    if not user:
        role = "admin" if email in ADMIN_EMAILS else "user"
        user = User(email=email, name=name, picture=picture, role=role, google_sub=sub)
        db.session.add(user)
    else:
        user.name = name
        user.picture = picture or user.picture
        user.google_sub = sub or user.google_sub
        if email in ADMIN_EMAILS and user.role != "admin":
            user.role = "admin"
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    login_user(user)
    log_audit("login", target_type="user", target_id=user.id, metadata_dict={"email": email})
    return redirect(url_for("dashboard"))

@app.route("/devlogin", methods=["GET","POST"])
def devlogin():
    # Optional, for local testing without Google OAuth. Controlled by ALLOW_DEV_LOGIN.
    if not ALLOW_DEV_LOGIN:
        abort(404)
    ensure_csrf()
    if request.method == "POST":
        email = (request.form.get("email","") or "").strip().lower()
        if not email:
            flash("メールを入力してください。", "error")
            return redirect(url_for("devlogin"))
        user = User.query.filter_by(email=email).first()
        if not user:
            role = "admin" if email in ADMIN_EMAILS else "user"
            user = User(email=email, name=email.split("@")[0], role=role)
            db.session.add(user); db.session.commit()
        login_user(user)
        log_audit("devlogin", target_type="user", target_id=user.id, metadata_dict={"email": email})
        return redirect(url_for("dashboard"))
    return render_template("devlogin.html")

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
    start = request.args.get("start"); end = request.args.get("end"); user_email = request.args.get("email", "").strip().lower()
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
    if user_email:
        q = q.filter(User.email == user_email)
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

    user_candidates = User.query.order_by(User.name.asc(), User.email.asc()).all()

    return render_template(
        "admin.html",
        shifts=shifts,
        start=start_date.isoformat(),
        end=end_date.isoformat(),
        user_email=user_email,
        daily_totals=daily_totals,
        user_candidates=user_candidates,
    )

def generate_csv(start_date, end_date, user_email=None):
    """CSVデータを生成する共通関数"""
    start_utc = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    end_utc = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)
    
    q = Shift.query.join(User).filter(Shift.clock_in_at >= start_utc, Shift.clock_in_at <= end_utc)
    if user_email:
        q = q.filter(User.email == user_email)
    shifts = q.order_by(Shift.clock_in_at.asc()).all()
    
    import csv
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["user_email","user_name","shift_id","clock_in_local","clock_out_local","worked_seconds","worked_hms","clock_in_utc","clock_out_utc","clock_in_ip","clock_out_ip","clock_in_ua","clock_out_ua","break_count","breaks_total_seconds","breaks_total_hms"])
    for s in shifts:
        in_local = s.clock_in_at.astimezone(LOCAL_TZ) if s.clock_in_at else None
        out_local = s.clock_out_at.astimezone(LOCAL_TZ) if s.clock_out_at else None
        worked = s.worked_seconds(); brk_sec = s.total_break_seconds()
        writer.writerow([
            s.user.email, s.user.name or "", s.id,
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
    now_local = datetime.now(LOCAL_TZ)
    default_end = now_local.date(); default_start = default_end - timedelta(days=13)
    try:
        start_date = datetime.fromisoformat(start).date() if start else default_start
        end_date = datetime.fromisoformat(end).date() if end else default_end
    except ValueError:
        abort(400, "日付の形式が不正です。YYYY-MM-DD で指定してください。")
    
    csv_data, shift_count = generate_csv(start_date, end_date, user_email if user_email else None)
    filename = f"attendance_export_{start_date.isoformat()}_{end_date.isoformat()}.csv"
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    log_audit("admin_export", target_type="shift", target_id=None, metadata_dict={"start": start_date.isoformat(), "end": end_date.isoformat(), "email": user_email, "shift_count": shift_count})
    return resp

def send_csv_email(to_email, csv_data, start_date, end_date):
    """CSVファイルをメールで送信"""
    try:
        smtp_host = os.getenv("SMTP_HOST", "localhost")
        smtp_port = int(os.getenv("SMTP_PORT", "25"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        smtp_use_tls = env_bool("SMTP_USE_TLS", False)
        
        msg = MIMEMultipart()
        msg["From"] = os.getenv("SMTP_FROM", smtp_user or "noreply@example.com")
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

def scheduled_csv_export():
    """定期CSVエクスポートのジョブ関数"""
    if not CSV_EXPORT_EMAIL:
        return
    
    with app.app_context():
        now_local = datetime.now(LOCAL_TZ)
        end_date = now_local.date()
        start_date = end_date - timedelta(days=CSV_EXPORT_DAYS)
        
        try:
            csv_data, shift_count = generate_csv(start_date, end_date)
            send_csv_email(CSV_EXPORT_EMAIL, csv_data, start_date, end_date)
            log_audit("scheduled_csv_export", target_type="system", target_id=None, 
                     metadata_dict={"email": CSV_EXPORT_EMAIL, "start": start_date.isoformat(), 
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
                         "user_email": shift.user.email,
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
        "user_email": shift.user.email,
        "user_name": shift.user.name,
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
    email = (request.args.get("email", "") or "").strip().lower()
    try:
        limit = int(request.args.get("limit", str(default_limit)))
    except ValueError:
        limit = default_limit
    limit = max(1, min(limit, max_limit))
    return action, email, limit

def _audit_log_query(action, email):
    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    if email:
        query = query.join(User).filter(db.func.lower(User.email) == email)
    return query

@app.route("/admin/audit")
@login_required
def admin_audit():
    """監査ログの閲覧"""
    require_admin()
    ensure_csrf()

    action, email, limit = _parse_audit_filters()
    query = _audit_log_query(action, email)
    logs = query.limit(limit).all()
    action_rows = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action.asc()).all()
    action_choices = [row[0] for row in action_rows]

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
        selected_email=email,
        limit=limit,
    )

@app.route("/admin/audit/export")
@login_required
def admin_audit_export():
    """監査ログのCSVエクスポート"""
    require_admin()
    action, email, limit = _parse_audit_filters(max_limit=5000, default_limit=1000)
    query = _audit_log_query(action, email)
    logs = query.limit(limit).all()

    import csv
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "created_at_local",
        "created_at_utc",
        "action",
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
            "email": email or None,
            "limit": limit,
            "count": len(logs),
        },
    )

    return resp

@app.route("/healthz")
def healthz():
    return "ok"

@app.before_request
def ensure_db():
    db.create_all()

@app.context_processor
def inject_globals():
    return {"current_user": current_user, "is_admin": (current_user.is_authenticated and current_user.is_admin()), "LOCAL_TZ_NAME": str(LOCAL_TZ), "ALLOW_DEV_LOGIN": ALLOW_DEV_LOGIN}

# 定期CSV送信のスケジューラー初期化
def init_scheduler():
    """スケジューラーを初期化"""
    if not CSV_EXPORT_EMAIL or not CSV_EXPORT_SCHEDULE:
        return None
    
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    
    scheduler = BackgroundScheduler()
    
    # スケジュール設定のパース
    schedule_lower = CSV_EXPORT_SCHEDULE.lower().strip()
    
    if schedule_lower == "daily":
        # 毎日 朝9時に実行
        trigger = CronTrigger(hour=9, minute=0, timezone=LOCAL_TZ)
    elif schedule_lower == "weekly":
        # 毎週月曜日 朝9時に実行
        trigger = CronTrigger(day_of_week="mon", hour=9, minute=0, timezone=LOCAL_TZ)
    elif schedule_lower == "monthly":
        # 毎月1日 朝9時に実行
        trigger = CronTrigger(day=1, hour=9, minute=0, timezone=LOCAL_TZ)
    elif " " in CSV_EXPORT_SCHEDULE and CSV_EXPORT_SCHEDULE.count(" ") >= 4:
        # cron形式（例: "0 9 * * *" → 毎日9時）
        try:
            parts = CSV_EXPORT_SCHEDULE.split()
            if len(parts) == 5:
                # CronTriggerのパラメータ: minute, hour, day, month, day_of_week
                trigger = CronTrigger(minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4], timezone=LOCAL_TZ)
            else:
                app.logger.warning(f"Invalid cron format: {CSV_EXPORT_SCHEDULE}")
                return None
        except Exception as e:
            app.logger.warning(f"Failed to parse cron schedule: {e}")
            return None
    else:
        app.logger.warning(f"Unknown schedule format: {CSV_EXPORT_SCHEDULE}")
        return None
    
    scheduler.add_job(func=scheduled_csv_export, trigger=trigger, id="csv_export_job", replace_existing=True)
    scheduler.start()
    app.logger.info(f"Scheduled CSV export initialized: {CSV_EXPORT_SCHEDULE} -> {CSV_EXPORT_EMAIL}")
    return scheduler

# アプリ起動時にスケジューラーを初期化
_scheduler = None
if CSV_EXPORT_EMAIL and CSV_EXPORT_SCHEDULE:
    try:
        _scheduler = init_scheduler()
    except Exception as e:
        app.logger.exception(f"Failed to initialize scheduler: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
