from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, text, inspect, ForeignKey, DateTime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps

from datetime import datetime
import unicodedata
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "daşlfsöşlöw#>£#½!!"

#Login User
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


#Create DB
class Base(DeclarativeBase):
    pass

def get_db_uri():
    uri = os.getenv("DATABASE_URL")
    if uri:
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        return uri
    return "sqlite:///students.db"

#Connect Database
app.config["SQLALCHEMY_DATABASE_URI"] = get_db_uri()
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class Masters(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    student_count: Mapped[int] = mapped_column(Integer, nullable=False)
    region: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    color: Mapped[str] = mapped_column(String(250))
    total_students: Mapped[int] = mapped_column(Integer, nullable=False, default=0,server_default="0",)

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="master")
    master_id: Mapped[int | None] = mapped_column(ForeignKey("masters.id"), nullable=True)
    master: Mapped["Masters"] = relationship("Masters", backref="users")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

masters_data = [
    ("Güzide Korkmaz", 3, "yeşil", "izmir"),
    ("Dilek Ceyhan", 3, "yeşil", "ankara"),
    ("Feride Özlem Gürkan", 0, "kırmızı", "adana"),
    ("Azize Eren", 1, "sarı", "antalya"),
    ("Esra Güldaş", 4, "yeşil", "aydın"),
    ("Gözde Şenkal", 0, "sarı", "istanbul"),
    ("Nurgül Civak", 0, "kırmızı", "zonguldak"),
    ("Ebru Aydoğan", 2, "sarı", "balıkesir"),
]

with app.app_context():
    db.create_all()

def compute_discount(monthly_students: int) -> int:
    if monthly_students >= 5: return 40
    if monthly_students >= 3: return 20
    if monthly_students >= 1: return 10
    return 0

def _normalize_tr(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)        # split diacritics
    s = s.replace("\u0307", "")                # remove dot-above (İ -> i)
    s = s.lower()
    for src, dst in [("ı","i"),("ğ","g"),("ü","u"),("ş","s"),("ö","o"),("ç","c")]:
        s = s.replace(src, dst)
    # drop remaining combining marks (safeguard)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    return s.strip()

def roles_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return deco

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.get("/admin/users/new")
@admin_required
def new_user_form():
    masters = db.session.scalars(db.select(Masters).order_by(Masters.name)).all()
    return render_template("admin_new_user.html", masters=masters)

@app.post("/admin/users")
@admin_required
def create_user():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    master_id = request.form.get("master_id")

    if not email or not password:
        return "Email and password are required", 400
    if db.session.scalar(db.select(User).where(User.email == email)):
        return "Email already exists", 400

    user = User(
        email=email,
        password_hash=generate_password_hash(password, salt_length=8),
        role="master" if master_id else "admin",
        master_id=int(master_id) if master_id else None
    )
    db.session.add(user)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/giris-yap', methods=["POST", "GET"])
def login():
    if request.method == "GET":
        return render_template('./login.html')

    username = request.form.get('username', '').strip().lower()
    password = request.form.get('password', '')

    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user or not check_password_hash(user.password_hash, password):
        return render_template('./error.html')
    login_user(user)
    return redirect(request.args.get("next") or url_for("dashboard"))

@app.route("/cikis")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
        
# routes.py / main.py

from flask_login import current_user

@app.route('/portal')
def dashboard():
    rows = db.session.scalars(db.select(Masters)).all()
    province_data = {
        _normalize_tr(r.region): {
            "name": r.name,
            "student_count": r.student_count,
            "color": r.color,
            "total_students": getattr(r, "total_students", None),
        } for r in rows
    }
    can_edit = current_user.is_authenticated and getattr(current_user, "role", None) in ("admin",)

    greeting_name = None
    monthly_students = 0
    discount = 0

    total_month = sum(r.student_count for r in rows)
    total_alltime = sum((r.total_ballots if False else r.total_students) for r in rows)

    if current_user.is_authenticated and getattr(current_user, "role", None) == "master":
        master = current_user.master
        if master:
            greeting_name = master.name
            monthly_students = master.student_count
            discount = compute_discount(monthly_students)

    return render_template(
        "dashboard.html",
        province_data=province_data,
        can_edit=can_edit,
        greeting_name=greeting_name,
        monthly_students=monthly_students,
        discount=discount,
        total_month=total_month,
        total_alltime=total_alltime,
    )

@app.get('/masters/new')
@roles_required('admin')
def master_form():
    return render_template('./master_form.html', form_mode="create", master=None)

@app.post('/masters')
@roles_required('admin')
def save_master():
    name = request.form.get('name','').strip()
    region = request.form.get('region','').strip()
    color = request.form.get('color','').strip()
    student_count = int(request.form.get('student_count','0') or 0)
    total_students = int(request.form.get('total_students','0') or 0)

    if not (name and region):
        return render_template('error.html'), 400

    existing = db.session.scalar(db.select(Masters).where(Masters.region == region))
    if existing:
        existing.name = name
        existing.color = color
        existing.student_count = student_count
        existing.total_students = total_students
    else:
        db.session.add(Masters(
            name=name,
            region=region,
            color=color,
            student_count=student_count,
            total_students=total_students,
        ))

    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/account")
@login_required
def account():
    return render_template("account.html")


if __name__ == '__main__':
    app.run(debug=True)