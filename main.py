from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, text, inspect, ForeignKey, DateTime, update
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

class Distributor(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    country: Mapped[str] = mapped_column(String(120), nullable=False)
    color: Mapped[str] = mapped_column(String(32), nullable=False, default="#2b6cb0")

    user: Mapped["User"] = relationship("User", backref="distributor_profile")

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

class Product(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)

class Purchase(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    distributor_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(ForeignKey("product.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    distributor: Mapped["User"] = relationship("User", backref="purchases")
    product: Mapped["Product"] = relationship("Product")

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

with app.app_context():
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

def compute_discount(monthly_students: int) -> int:
    if monthly_students >= 5: return 40
    if monthly_students >= 3: return 20
    if monthly_students >= 1: return 10
    return 0

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


@app.get("/admin/kullanicilar/yeni")
@admin_required
def new_user_form():
    masters = db.session.scalars(db.select(Masters).order_by(Masters.name)).all()
    return render_template("admin_new_user.html", masters=masters)

@app.post("/admin/kullanicilar")
@admin_required
def create_user():
    email = request.form.get("email","")
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

    # Normalize ONLY the username
    username = (request.form.get('username', '') or '')
    # Keep the password exactly as typed
    password = (request.form.get('password', '') or '')

    # Single lookup
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user or not check_password_hash(user.password_hash, password):
        # Optional: flash a message here
        return render_template('./error.html'), 401

    login_user(user)

    # Route based on role
    next_url = request.args.get("next")
    if user.role == "distributor":
        return redirect(next_url or url_for("distributor_home"))
    elif user.role == "admin":
        return redirect(next_url or url_for("dashboard"))
    elif user.role == "master":
        return redirect(next_url or url_for("dashboard"))
    else:
        # Fallback if an unknown role is stored
        return redirect(url_for("index"))


@app.route("/cikis")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route('/portal')
@login_required
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

@app.get("/distributor/portal")
@login_required
def distributor_home():
    rows = db.session.scalars(db.select(Distributor)).all()
    distributor_data = {
        _normalize_tr(d.country): {"name": d.name, "color": d.color}
        for d in rows
    }

    if current_user.role == "admin":
        distributor_id = request.args.get("distributor_id", type=int)
    else:
        distributor_id = current_user.id  # distributors see their own

    purchases_summary = []
    if distributor_id:
        purchases_summary = db.session.execute(
            db.select(
                Product.name.label("product"),
                db.func.sum(Purchase.quantity).label("quantity")
            )
            .join(Purchase.product)
            .where(Purchase.distributor_id == distributor_id)
            .group_by(Product.name)
            .order_by(Product.name)
        ).all()

    total_purchases = db.session.execute(db.select(
        Purchase.id,
        User.username.label('distributor_name'),
        Product.name.label('product_name'),
        Purchase.quantity,
        Purchase.created_at
        ).join(User, Purchase.distributor_id == User.id)
        .join(Product, Purchase.product_id == Product.id)
        .order_by(Purchase.created_at.desc())
        .limit(10)
        ).all()

    return render_template(
        "distributor.html",
        distributor_data=distributor_data,
        purchases_summary=purchases_summary,
        total_purchases=total_purchases
    )


@app.get("/admin/satin-alimlar/yeni")
@admin_required
def purchase_form():
    distributors = db.session.scalars(
        db.select(User).where(User.role == "distributor").order_by(User.username)
    ).all()
    products = db.session.scalars(
        db.select(Product).order_by(Product.name)
    ).all()
    return render_template("admin_purchase_form.html", distributors=distributors, products=products)

@app.post("/admin/satin-alimlar")
@admin_required
def create_purchase():
    distributor_id = request.form.get("distributor_id")
    product_id = request.form.get("product_id")
    qty_raw = request.form.get("quantity", "0")

    try:
        distributor_id = int(distributor_id)
        product_id = int(product_id)
        quantity = int(qty_raw)
    except (TypeError, ValueError):
        return "Invalid input", 400

    if quantity <= 0:
        return "Quantity must be > 0", 400

    distributor = db.session.get(User, distributor_id)
    if not distributor or distributor.role != "distributor":
        return "Invalid distributor", 400

    product = db.session.get(Product, product_id)
    if not product:
        return "Invalid product", 400

    db.session.add(Purchase(distributor_id=distributor_id, product_id=product_id, quantity=quantity))
    db.session.commit()
    return redirect(url_for("purchase_form"))


@app.get('/masters/yeni-master')
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

@app.route("/hesap")
@roles_required('master')
@login_required
def account():
    return render_template("account.html")

@app.route("/admin/tum-satin-alimlar")
@admin_required
def all_purchases():
    purchases = db.session.execute(
        db.select(
            Purchase.id,
            User.username.label("distributor_name"),
            Product.name.label("product_name"),
            Purchase.quantity,
            Purchase.created_at
        )
        .join(User, Purchase.distributor_id == User.id)
        .join(Product, Purchase.product_id == Product.id)
        .order_by(Purchase.created_at.desc())
    ).all()

    return render_template("admin_all_purchases.html", purchases=purchases)

@app.get("/admin/distributors/new")
@admin_required
def new_distributor_form():
    return render_template("admin_new_distributor.html")

@app.post("/admin/distributors")
@admin_required
def create_distributor():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    full_name = (request.form.get("full_name") or "").strip()
    country = (request.form.get("country") or "").strip()
    color = (request.form.get("color") or "#2b6cb0").strip()

    if not (username and password and full_name and country):
        return "Tüm alanların (kullanıcı adı, şifre, isim, ülke) doldurulması zorunludur.", 400

    if db.session.scalar(db.select(User).where(User.username == username)):
        return "Kullanıcı adı zaten var.", 400

    user = User(
        username=username,
        password_hash=generate_password_hash(password, salt_length=8),
        role="distributor",
    )
    db.session.add(user)
    db.session.flush() 

    dist = Distributor(
        user_id=user.id,
        name=full_name,
        country=country, 
        color=color or "#2b6cb0",
    )
    db.session.add(dist)
    db.session.commit()

    return redirect(url_for("distributor_home"))

@app.get("/admin/masters/new")
@admin_required
def new_master_form():
    return render_template("admin_new_master.html")

@app.post("/admin/masters")
@admin_required
def create_master():
    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""

    full_name = (request.form.get("full_name") or "").strip()
    region = (request.form.get("region") or "").strip()           
    color = (request.form.get("color") or "#22c55e").strip()     

    student_count_raw = request.form.get("student_count", "0")
    total_students_raw = request.form.get("total_students", "0")

    if not (username and password and full_name and region):
        return "Tüm alanların doldurulması zorunludur.", 400
    if db.session.scalar(db.select(User).where(User.username == username)):
        return "Username already exists.", 400

    try:
        student_count = int(student_count_raw or 0)
        total_students = int(total_students_raw or 0)
    except ValueError:
        return "Öğrenci sayısı rakam olmak zorundadır.", 400

    master = Masters(
        name=full_name,
        region=region,
        color=color,
        student_count=student_count,
        total_students=total_students,
    )
    db.session.add(master)
    db.session.flush()  

    user = User(
        username=username,
        password_hash=generate_password_hash(password, salt_length=8),
        role="master",
        master_id=master.id,
    )
    db.session.add(user)
    db.session.commit()

    return redirect(url_for("dashboard"))


if __name__ == '__main__':
    app.run(debug=True)