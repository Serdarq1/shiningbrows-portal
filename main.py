from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, text, inspect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps

import unicodedata
import os
import json
import requests

app = Flask(__name__)
app.config["SECRET_KEY"] = "daşlfsöşlöw#>£#½!!"

#Credentials
admin_username = os.getenv('SHININGBROWS_USERNAME', 'admin')
admin_password = os.getenv('SHININGBROWS_PASSWORD')
admin_hashed = generate_password_hash(admin_password, salt_length=8)

#Authorized
authorized_username = os.getenv('SHININGBROWSADMIN', 'authorized')
authorized_password = os.getenv('SHININGBROWSADMIN_PASSWORD')
authorized_hashed = generate_password_hash(authorized_password, salt_length=8)

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

class User(UserMixin):
    def __init__(self, role: str, name: str = "User"):
        self.id = role
        self.role = role
        self.name = name

@login_manager.user_loader
def load_user(user_id):
    if user_id in ("admin", "authorized"):
        return User(role=user_id, name=user_id.title())
    return None

with app.app_context():
    insp = inspect(db.engine)
    cols = [c["name"] for c in insp.get_columns("masters")]
    if "total_students" not in cols:
        db.session.execute(
            text("ALTER TABLE masters ADD COLUMN total_students INTEGER DEFAULT 0")
        )
        db.session.commit()
        print("✅ Added total_students column.")
    else:
        print("ℹ️ total_students already exists.")
    
    db.create_all()


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

def verify_login(username: str, password: str):
    if username == admin_username and check_password_hash(admin_hashed, password):
        return User(role="admin", name="Admin")
    if username == authorized_username and check_password_hash(authorized_hashed, password):
        return User(role="authorized", name="Authorized")
    return None

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
    return roles_required("admin")(view)


@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/giris-yap', methods=["POST", "GET"])
def login():
    if request.method == "GET":
        return render_template('./login.html')

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    user = verify_login(username, password)
    if not user:
        return render_template('./error.html')

    login_user(user)
    next_url = request.args.get('next') or url_for('dashboard')
    return redirect(next_url)
        
@app.route('/portal')
@roles_required("authorized", "admin")
def dashboard():
    rows = db.session.scalars(db.select(Masters)).all()
    province_data = {
        _normalize_tr(r.region): {
            "name": r.name,
            "student_count": r.student_count,
            "total_students": r.total_students,
            "color": r.color
        } for r in rows
    }
    print(province_data)
    return render_template('./dashboard.html', province_data=province_data)

@app.get('/masters/new')
@roles_required("authorized")
def master_form():
    return render_template('./master_form.html', form_mode="create", master=None)

@app.post('/masters')
@roles_required("authorized")
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


if __name__ == '__main__':
    app.run(debug=True)