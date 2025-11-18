from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, text, inspect, ForeignKey, DateTime, update, func, desc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps

from datetime import datetime
import unicodedata
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "daşlfsöşlöw#>£#½!!"
# Increase wait time for busy DB
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"timeout": 30},  # seconds
}


#Login User
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#Create DB
class Base(DeclarativeBase):
    pass

def get_db_uri():
    uri = os.getenv("DATABASE_URL")

    if not uri:
        return "sqlite:///students.db"

    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql+psycopg2://", 1)

    if uri.startswith("postgresql://") and "psycopg2" not in uri:
        uri = uri.replace("postgresql://", "postgresql+psycopg2://", 1)

    return uri

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
    contract_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(
        "User",
        backref=db.backref("distributor_profile", uselist=False),
        uselist=False
    )

class Masters(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    student_count: Mapped[int] = mapped_column(Integer, nullable=False)
    region: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    color: Mapped[str] = mapped_column(String(250))
    total_students: Mapped[int] = mapped_column(Integer, nullable=False, default=0,server_default="0")
    contract_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   

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

    contract_date = None
    contract_end = None
    now = datetime.now()

    if current_user.is_authenticated and getattr(current_user, "role", None) == "master":
        master = current_user.master
        if master:
            greeting_name = master.name
            try:
                contract_date = master.contract_date
                contract_end = master.contract_date.replace(year=master.contract_date.year + 1)
            except Exception:
                contract_date = None
                contract_end = None
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
        contract_date=contract_date,
        contract_end=contract_end,
        now=now
    )

@app.get("/distributor/portal")
@login_required
@roles_required('distributor', 'admin')
def distributor_home():
    rows = db.session.scalars(db.select(Distributor)).all()
    now = datetime.now()

    distributor_data = {
        _normalize_tr(d.country): {
            "name": d.name,
            "color": d.color,
            "contract_date": d.contract_date.strftime("%Y-%m-%d") if d.contract_date else None,
        }
        for d in rows
    }

    if current_user.role == "admin":
        distributor_id = request.args.get("distributor_id", type=int)
    else:
        distributor_id = current_user.id

    distributor_name = None
    distributor_contract_date = None
    distributor_contract_date_end = None
    distributor_region = None

    if current_user.role == "distributor" and current_user.distributor_profile:
        prof = current_user.distributor_profile
        distributor_name = prof.name
        distributor_contract_date = prof.contract_date
        distributor_region = prof.country
        distributor_contract_date_end = (
            prof.contract_date.replace(year=prof.contract_date.year + 1)
            if prof.contract_date else None
        )

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

    # Build per-country, per-product totals (including zeros)
    dist_rows = db.session.execute(
        db.select(Distributor.country, Distributor.user_id)
    ).all()

    def _norm(s: str) -> str:
        import unicodedata
        if not s: return ""
        s = unicodedata.normalize("NFD", s).replace("\u0307","").lower()
        for a,b in [("ı","i"),("ğ","g"),("ü","u"),("ş","s"),("ö","o"),("ç","c")]:
            s = s.replace(a,b)
        return "".join(ch for ch in s if unicodedata.category(ch) != "Mn").strip()

    country_to_distid = { _norm(c): uid for (c, uid) in dist_rows }

    all_products = [
        p.name for p in db.session.scalars(db.select(Product).order_by(Product.name)).all()
    ]

    agg = db.session.execute(
        db.select(Purchase.distributor_id, Product.name, db.func.sum(Purchase.quantity))
          .join(Product, Purchase.product_id == Product.id)
          .group_by(Purchase.distributor_id, Product.name)
    ).all()

    from collections import defaultdict
    dist_totals = defaultdict(lambda: {name: 0 for name in all_products})
    for dist_id, prod_name, qty in agg:
        dist_totals[dist_id][prod_name] = int(qty or 0)

    purchases_by_country = {}
    for c_norm, dist_id in country_to_distid.items():
        totals = dist_totals.get(dist_id, {name: 0 for name in all_products})
        purchases_by_country[c_norm] = [
            {"product": name, "quantity": int(totals.get(name, 0))}
            for name in all_products
        ]

    return render_template(
        "distributor.html",
        distributor_data=distributor_data,
        purchases_summary=purchases_summary,
        distributor_contract_date=distributor_contract_date,
        distributor_contract_date_end=distributor_contract_date_end,
        distributor_name=distributor_name,
        distributor_id=distributor_id,
        distributor_region=distributor_region,
        now=now,
        purchases_by_country=purchases_by_country,
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

@app.post("/admin/purchases")
@admin_required
def create_purchase():
    distributor_id_raw = request.form.get("distributor_id")
    product_ids = request.form.getlist("product_id[]")
    quantities = request.form.getlist("quantity[]")

    try:
        distributor_id = int(distributor_id_raw)
    except (TypeError, ValueError):
        return "Invalid distributor", 400

    distributor = db.session.get(User, distributor_id)
    if not distributor or distributor.role != "distributor":
        return "Invalid distributor", 400

    for prod_id_raw, qty_raw in zip(product_ids, quantities):
        try:
            prod_id = int(prod_id_raw)
            qty = int(qty_raw)
        except (TypeError, ValueError):
            continue

        if qty <= 0:
            continue

        product = db.session.get(Product, prod_id)
        if not product:
            continue

        db.session.add(Purchase(
            distributor_id=distributor_id,
            product_id=prod_id,
            quantity=qty
        ))

    db.session.commit()

    return redirect(url_for("all_purchases"))



@app.get("/masters/duzenle")
@roles_required("admin")
def master_edit_form():
    masters = db.session.scalars(db.select(Masters).order_by(Masters.name)).all()
    return render_template(
        "master_form.html",
        masters=masters
    )


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
@login_required
def account():
    password_status = request.args.get("password_status", default="", type=str)
    return render_template("account.html", password_status=password_status)


@app.post("/hesap/sifre-degistir")
@roles_required('master', 'admin')
@login_required
def change_password():
    current_password = (request.form.get("current_password") or "").strip()
    new_password = (request.form.get("new_password") or "").strip()
    confirm_password = (request.form.get("confirm_password") or "").strip()

    if not check_password_hash(current_user.password_hash, current_password):
        return redirect(url_for("account", password_status="invalid-current"))

    if len(new_password) < 6:
        return redirect(url_for("account", password_status="too-short"))

    if new_password != confirm_password:
        return redirect(url_for("account", password_status="mismatch"))

    current_user.password_hash = generate_password_hash(new_password, salt_length=8)
    db.session.add(current_user)
    db.session.commit()

    return redirect(url_for("account", password_status="success"))


@app.get("/admin/tum-satin-alimlar")
@admin_required
def all_purchases():
    # ---- Filters ----
    q_distributor = request.args.get("distributor", "", type=str).strip()
    q_product     = request.args.get("product", "", type=str).strip()
    q_from        = request.args.get("from", "", type=str)
    q_to          = request.args.get("to", "", type=str)
    page          = max(request.args.get("page", 1, type=int), 1)
    per_page      = min(request.args.get("per_page", 25, type=int), 200)

    base = (
        db.select(
            Purchase.id,
            User.username.label('distributor_name'),
            Product.name.label('product_name'),
            Purchase.quantity,
            Purchase.created_at,
        )
        .join(User, Purchase.distributor_id == User.id)
        .join(Product, Purchase.product_id == Product.id)
    )

    # Apply filters
    if q_distributor:
        base = base.where(User.username.ilike(f"%{q_distributor}%"))
    if q_product:
        base = base.where(Product.name.ilike(f"%{q_product}%"))

    # date filter
    from_dt = to_dt = None
    try:
        if q_from:
            from_dt = datetime.fromisoformat(q_from)
            base = base.where(Purchase.created_at >= from_dt)
        if q_to:
            # inclusive end-of-day if only date provided
            to_dt = datetime.fromisoformat(q_to)
            base = base.where(Purchase.created_at <= to_dt)
    except ValueError:
        pass  # ignore bad date formats gracefully

    base = base.order_by(desc(Purchase.created_at))

    # Pagination (server-side)
    total_count = db.session.execute(
        base.with_only_columns(func.count()).order_by(None)
    ).scalar_one()

    rows = db.session.execute(
        base.limit(per_page).offset((page-1)*per_page)
    ).all()

    # ---- Aggregates for tabs ----
    by_distributor = db.session.execute(
        db.select(
            User.username.label("distributor_name"),
            func.sum(Purchase.quantity).label("total_qty")
        )
        .join(User, Purchase.distributor_id == User.id)
        .group_by(User.username)
        .order_by(desc(func.sum(Purchase.quantity)))
    ).all()

    by_product = db.session.execute(
        db.select(
            Product.name.label("product_name"),
            func.sum(Purchase.quantity).label("total_qty")
        )
        .join(Product, Purchase.product_id == Product.id)
        .group_by(Product.name)
        .order_by(desc(func.sum(Purchase.quantity)))
    ).all()

    # KPIs
    kpi_total_units = db.session.execute(
        db.select(func.coalesce(func.sum(Purchase.quantity), 0))
    ).scalar_one()
    kpi_total_orders = db.session.execute(
        db.select(func.count(Purchase.id))
    ).scalar_one()
    kpi_distinct_distributors = db.session.execute(
        db.select(func.count(func.distinct(Purchase.distributor_id)))
    ).scalar_one()

    distributors = [r[0] for r in db.session.execute(
        db.select(User.username).distinct()
        .join(Purchase, Purchase.distributor_id == User.id)
        .order_by(User.username)
    ).all()]

    products = [r[0] for r in db.session.execute(
        db.select(Product.name).distinct()
        .join(Purchase, Purchase.product_id == Product.id)
        .order_by(Product.name)
    ).all()]

    return render_template(
        "admin_all_purchases.html",
        purchases=rows,
        total_count=total_count,
        page=page, per_page=per_page,
        by_distributor=by_distributor,
        by_product=by_product,
        kpi_total_units=kpi_total_units,
        kpi_total_orders=kpi_total_orders,
        kpi_distinct_distributors=kpi_distinct_distributors,
        q_distributor=q_distributor, q_product=q_product, q_from=q_from, q_to=q_to,
        distributors=distributors,
        products=products     
    )

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

@app.get("/admin/masters/yeni-master")
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


@app.post("/admin/reset-data")
@admin_required
def reset_data():
    masters = db.session.scalars(db.select(Masters)).all()
    for m in masters:
        m.student_count = 0
        m.total_students = 0

    db.session.execute(db.delete(Purchase))

    db.session.commit()

    return "Tüm öğrenci sayıları ve satın alımlar sıfırlanmıştır.", 200

if __name__ == '__main__':
    app.run(debug=True)
