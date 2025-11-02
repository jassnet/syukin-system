#!/usr/bin/env python3
import os
import secrets
import hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

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

db = SQLAlchemy(app)

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
    return local.strftime("%Y-%m-%d %H:%M:%S")

@app.template_filter("fmt_hms")
def fmt_hms(seconds):
    seconds = int(seconds or 0)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

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
    return render_template("admin.html", shifts=shifts, start=start_date.isoformat(), end=end_date.isoformat(), user_email=user_email)

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
    csv_data = buf.getvalue().encode("utf-8-sig")
    filename = f"attendance_export_{start_date.isoformat()}_{end_date.isoformat()}.csv"
    resp = make_response(csv_data); resp.headers["Content-Type"] = "text/csv; charset=utf-8"; resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    log_audit("admin_export", target_type="shift", target_id=None, metadata_dict={"start": start_date.isoformat(), "end": end_date.isoformat(), "email": user_email})
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
