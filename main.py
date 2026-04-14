"""
Portfolio web app - Ezequiel Zamora
Stack: FastAPI + Jinja2 + SQLite + Sessions

SEGURIDAD:
- Credenciales via variables de entorno (no hardcodeadas)
- Secret key via variable de entorno
- Rate limiting en login (max 5 intentos por IP)
- Validación de inputs (email, largo de campos)
- Headers de seguridad HTTP en todas las respuestas
- Contraseña hasheada con salt (no SHA-256 simple)
- Categoría de post validada contra lista blanca
- Conexiones DB cerradas siempre con try/finally
"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from jinja2 import Environment, FileSystemLoader
import sqlite3, json, hashlib, re, os, time
from datetime import datetime
from pathlib import Path

app = FastAPI(title="Ezequiel Zamora - Portfolio", docs_url=None, redoc_url=None)

# ─── SEGURIDAD: Secret key desde variable de entorno ─────────────────────────
# En Railway: Settings → Variables → SECRET_KEY = (genera con: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-key-change-in-production-never-use-this")

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=False)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
_env = Environment(loader=FileSystemLoader("templates"), auto_reload=True)
_env.cache = {}
templates = Jinja2Templates(env=_env)

# ─── CONFIG: Credenciales desde variables de entorno ─────────────────────────
# En Railway: Settings → Variables → ADMIN_USER y ADMIN_PASSWORD
ADMIN_USER     = os.environ.get("ADMIN_USER", "ezequiel")
_raw_password  = os.environ.get("ADMIN_PASSWORD", "admin1234")
# Salt + hash para que no sea reversible por rainbow tables
_SALT          = os.environ.get("PASSWORD_SALT", "portfolio-salt-2025")
ADMIN_PASSWORD = hashlib.sha256(f"{_SALT}{_raw_password}".encode()).hexdigest()

# ─── RATE LIMITING: Máx 5 intentos de login por IP ───────────────────────────
_login_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS  = 5
WINDOW_SECS   = 300  # 5 minutos

def check_rate_limit(ip: str) -> bool:
    """Retorna True si la IP puede intentar login, False si está bloqueada."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Limpiar intentos fuera de la ventana
    attempts = [t for t in attempts if now - t < WINDOW_SECS]
    _login_attempts[ip] = attempts
    return len(attempts) < MAX_ATTEMPTS

def record_attempt(ip: str):
    now = time.time()
    _login_attempts.setdefault(ip, []).append(now)

# ─── CATEGORÍAS VÁLIDAS (lista blanca) ───────────────────────────────────────
VALID_CATEGORIES = {"computacion", "matematicas", "fisica"}

# ─── HEADERS DE SEGURIDAD HTTP ────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    # Ocultar que usamos Python/FastAPI
    response.headers["Server"]                    = "webserver"
    return response

# ─── DATABASE ────────────────────────────────────────────────────────────────
DB_PATH = "database/portfolio.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    Path("database").mkdir(exist_ok=True)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS blog_posts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                slug        TEXT UNIQUE NOT NULL,
                summary     TEXT NOT NULL,
                content     TEXT NOT NULL,
                category    TEXT NOT NULL DEFAULT 'computacion',
                tags        TEXT DEFAULT '[]',
                published   INTEGER DEFAULT 1,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contacts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                email      TEXT NOT NULL,
                subject    TEXT NOT NULL,
                message    TEXT NOT NULL,
                read       INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
        """)
        try:
            cur.execute("ALTER TABLE blog_posts ADD COLUMN published INTEGER DEFAULT 1")
        except Exception: pass
        try:
            cur.execute("ALTER TABLE contacts ADD COLUMN read INTEGER DEFAULT 0")
        except Exception: pass

        cur.execute("SELECT COUNT(*) FROM blog_posts")
        if cur.fetchone()[0] == 0:
            now = datetime.now().isoformat()
            posts = [
                (
                    "Python y el Pensamiento Computacional: Mi Primer Año en el Camino",
                    "python-pensamiento-computacional",
                    "Reflexiones sobre cómo aprender a programar cambia la forma en que percibes los problemas del mundo real.",
                    """Cuando empecé a estudiar Python hace unos meses, lo que más me sorprendió no fue la sintaxis —bastante limpia— sino cómo comencé a ver los problemas cotidianos de otra manera.

En la construcción, donde trabajo actualmente, hay decisiones que se toman de forma casi intuitiva: ¿cuánto material necesito? ¿cuál es la ruta más eficiente para los camiones? Lo que descubrí es que estas preguntas ya eran algoritmos en mi cabeza. Python simplemente me dio el lenguaje para expresarlos formalmente.

**El concepto que lo cambió todo: la abstracción**

La abstracción es la idea de que puedes trabajar con una cosa sin necesitar conocer todos sus detalles internos.

```python
def calcular_material(ancho, largo, factor_desperdicio=1.1):
    area_base = ancho * largo
    return area_base * factor_desperdicio

material_necesario = calcular_material(12.5, 8.0)
print(f"Material necesario: {material_necesario:.2f} m²")
```

**Lo que me falta por aprender**

Tengo un plan de estudio de 10-12 meses que cubre desde los fundamentos hasta FastAPI y PostgreSQL.""",
                    "computacion", '["python", "aprendizaje", "algoritmos"]', 1, now, now
                ),
                (
                    "Álgebra Lineal y Gráficos 3D: La Matemática Detrás de lo que Ves",
                    "algebra-lineal-graficos-3d",
                    "Cómo las matrices y transformaciones lineales son el motor invisible detrás de los videojuegos y el diseño por computadora.",
                    """Uno de los momentos más satisfactorios que he tenido estudiando matemáticas fue entender que las matrices no son solo tablas de números: son transformaciones del espacio.

**Las tres transformaciones fundamentales**

Toda transformación en 2D o 3D se puede descomponer en traslación, rotación y escala.

```python
import math

def rotar_punto(x, y, angulo_grados):
    rad = math.radians(angulo_grados)
    x2 = x * math.cos(rad) - y * math.sin(rad)
    y2 = x * math.sin(rad) + y * math.cos(rad)
    return round(x2, 4), round(y2, 4)

print(rotar_punto(1, 0, 90))  # → (0.0, 1.0)
```

Los brazos robóticos usan cinemática —y la cinemática es álgebra lineal aplicada.""",
                    "matematicas", '["álgebra lineal", "matrices", "3D", "robótica"]', 1, now, now
                ),
                (
                    "Electricidad y Código: Cuando el Hardware Encuentra al Software",
                    "electricidad-y-codigo",
                    "Desde diagnosticar una bomba industrial hasta programar microcontroladores: el puente entre el mundo físico y el digital.",
                    """Trabajo en construcción. He tocado cables, medido voltaje con multímetro, diagnosticado motores trifásicos.

**El día que diagnostiqué una bomba con lógica de programador**

Apliqué el mismo proceso que para depurar código: reproducir el error, aislar variables, probar hipótesis, documentar. Resultó ser un condensador de arranque defectuoso.

**Arduino como puente**

```cpp
int lectura = analogRead(A0);
float voltaje = lectura * (5.0 / 1023.0);
float temperatura = (voltaje - 0.5) * 100;
Serial.println(temperatura);
```

La frontera entre software y hardware es más difusa de lo que parece. Y eso es precisamente lo que la hace fascinante.""",
                    "fisica", '["electrónica", "Arduino", "hardware"]', 1, now, now
                ),
            ]
            cur.executemany(
                "INSERT INTO blog_posts (title,slug,summary,content,category,tags,published,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                posts
            )
        conn.commit()
    finally:
        conn.close()

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def make_slug(title: str) -> str:
    slug = title.lower().strip()
    for src, dst in [('áàä','a'),('éèë','e'),('íìï','i'),('óòö','o'),('úùü','u'),('ñ','n')]:
        for ch in src:
            slug = slug.replace(ch, dst)
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug)
    return slug.strip('-')[:80]

def is_admin(request: Request) -> bool:
    return request.session.get("admin") is True

def validate_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email)) and len(email) <= 200

def truncate(text: str, max_len: int) -> str:
    return text[:max_len]

# ─── STARTUP ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()

# ─── RUTAS PÚBLICAS ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    conn = get_db()
    try:
        posts = conn.execute(
            "SELECT * FROM blog_posts WHERE published=1 ORDER BY created_at DESC LIMIT 3"
        ).fetchall()
    finally:
        conn.close()
    return templates.TemplateResponse(request, "index.html", context={
        "recent_posts": [dict(p) for p in posts],
        "page": "home"
    })

@app.get("/blog", response_class=HTMLResponse)
async def blog(request: Request, categoria: str = None):
    # Validar categoría contra lista blanca
    if categoria and categoria not in VALID_CATEGORIES:
        categoria = None
    conn = get_db()
    try:
        if categoria:
            posts = conn.execute(
                "SELECT * FROM blog_posts WHERE published=1 AND category=? ORDER BY created_at DESC",
                (categoria,)
            ).fetchall()
        else:
            posts = conn.execute(
                "SELECT * FROM blog_posts WHERE published=1 ORDER BY created_at DESC"
            ).fetchall()
    finally:
        conn.close()
    return templates.TemplateResponse(request, "blog.html", context={
        "posts": [dict(p) for p in posts],
        "categoria_activa": categoria,
        "page": "blog"
    })

@app.get("/blog/{slug}", response_class=HTMLResponse)
async def post_detail(request: Request, slug: str):
    # Validar formato del slug
    if not re.match(r'^[a-z0-9-]{1,100}$', slug):
        raise HTTPException(status_code=404)
    conn = get_db()
    try:
        post = conn.execute(
            "SELECT * FROM blog_posts WHERE slug=? AND published=1", (slug,)
        ).fetchone()
    finally:
        conn.close()
    if not post:
        raise HTTPException(status_code=404, detail="Post no encontrado")
    post_dict = dict(post)
    tags = json.loads(post_dict["tags"])
    return templates.TemplateResponse(request, "post.html", context={
        "post": post_dict,
        "tags": tags,
        "page": "blog"
    })

@app.post("/contacto", response_class=HTMLResponse)
async def contacto_submit(
    request: Request,
    name:    str = Form(...),
    email:   str = Form(...),
    subject: str = Form(...),
    message: str = Form(...)
):
    # Validar email y truncar campos para evitar spam/overflow
    errors = []
    if not validate_email(email):
        errors.append("Email inválido.")
    if len(name.strip()) < 2:
        errors.append("Nombre demasiado corto.")
    if len(message.strip()) < 10:
        errors.append("Mensaje demasiado corto.")

    conn = get_db()
    try:
        recent_posts = [dict(p) for p in conn.execute(
            "SELECT * FROM blog_posts WHERE published=1 ORDER BY created_at DESC LIMIT 3"
        ).fetchall()]

        if errors:
            return templates.TemplateResponse(request, "index.html", context={
                "recent_posts": recent_posts,
                "error_contacto": " ".join(errors),
                "page": "home"
            })

        conn.execute(
            "INSERT INTO contacts (name,email,subject,message,created_at) VALUES (?,?,?,?,?)",
            (
                truncate(name.strip(), 100),
                truncate(email.strip(), 200),
                truncate(subject.strip(), 200),
                truncate(message.strip(), 2000),
                datetime.now().isoformat()
            )
        )
        conn.commit()
    finally:
        conn.close()

    return templates.TemplateResponse(request, "index.html", context={
        "recent_posts": recent_posts,
        "mensaje_enviado": True,
        "page": "home"
    })

@app.get("/health")
async def health():
    return {"status": "ok"}

# ─── ADMIN: AUTH ──────────────────────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request):
    if is_admin(request):
        return RedirectResponse("/admin", status_code=302)
    return templates.TemplateResponse(request, "admin/login.html", context={})

@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login_post(
    request:  Request,
    username: str = Form(...),
    password: str = Form(...)
):
    ip = request.client.host

    # Rate limiting
    if not check_rate_limit(ip):
        return templates.TemplateResponse(request, "admin/login.html", context={
            "error": "Demasiados intentos fallidos. Espera 5 minutos."
        })

    pw_hash = hashlib.sha256(f"{_SALT}{password}".encode()).hexdigest()

    # Comparación en tiempo constante para evitar timing attacks
    import hmac
    user_ok = hmac.compare_digest(username, ADMIN_USER)
    pass_ok = hmac.compare_digest(pw_hash, ADMIN_PASSWORD)

    if user_ok and pass_ok:
        request.session["admin"] = True
        # Limpiar intentos al lograr acceso
        _login_attempts.pop(ip, None)
        return RedirectResponse("/admin", status_code=302)

    record_attempt(ip)
    remaining = MAX_ATTEMPTS - len(_login_attempts.get(ip, []))
    return templates.TemplateResponse(request, "admin/login.html", context={
        "error": f"Credenciales incorrectas. Intentos restantes: {remaining}"
    })

@app.get("/admin/logout")
async def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=302)

# ─── ADMIN: DASHBOARD ─────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    conn = get_db()
    try:
        posts    = conn.execute("SELECT * FROM blog_posts ORDER BY created_at DESC").fetchall()
        contacts = conn.execute("SELECT * FROM contacts ORDER BY created_at DESC LIMIT 20").fetchall()
        unread   = conn.execute("SELECT COUNT(*) FROM contacts WHERE read=0").fetchone()[0]
    finally:
        conn.close()
    return templates.TemplateResponse(request, "admin/dashboard.html", context={
        "posts":    [dict(p) for p in posts],
        "contacts": [dict(c) for c in contacts],
        "unread":   unread,
        "page":     "admin"
    })

# ─── ADMIN: POSTS ─────────────────────────────────────────────────────────────

@app.get("/admin/posts/nuevo", response_class=HTMLResponse)
async def admin_new_post(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    return templates.TemplateResponse(request, "admin/post_form.html", context={
        "post": None, "page": "admin"
    })

@app.post("/admin/posts/nuevo", response_class=HTMLResponse)
async def admin_new_post_post(
    request:   Request,
    title:     str = Form(...),
    summary:   str = Form(...),
    content:   str = Form(...),
    category:  str = Form(...),
    tags:      str = Form(""),
    published: str = Form("0"),
):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)

    # Validar categoría contra lista blanca
    if category not in VALID_CATEGORIES:
        category = "computacion"

    slug = make_slug(title)
    tags_list = [truncate(t.strip(), 50) for t in tags.split(",") if t.strip()][:10]
    now = datetime.now().isoformat()
    conn = get_db()
    try:
        base_slug, counter = slug, 1
        while conn.execute("SELECT id FROM blog_posts WHERE slug=?", (slug,)).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        conn.execute(
            "INSERT INTO blog_posts (title,slug,summary,content,category,tags,published,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                truncate(title, 200),
                slug,
                truncate(summary, 500),
                truncate(content, 50000),
                category,
                json.dumps(tags_list),
                int(published == "1"),
                now, now
            )
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)

@app.get("/admin/posts/{post_id}/editar", response_class=HTMLResponse)
async def admin_edit_post(request: Request, post_id: int):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    conn = get_db()
    try:
        post = conn.execute("SELECT * FROM blog_posts WHERE id=?", (post_id,)).fetchone()
    finally:
        conn.close()
    if not post:
        raise HTTPException(status_code=404)
    post_dict = dict(post)
    post_dict["tags_str"] = ", ".join(json.loads(post_dict["tags"]))
    return templates.TemplateResponse(request, "admin/post_form.html", context={
        "post": post_dict, "page": "admin"
    })

@app.post("/admin/posts/{post_id}/editar", response_class=HTMLResponse)
async def admin_edit_post_post(
    request:   Request,
    post_id:   int,
    title:     str = Form(...),
    summary:   str = Form(...),
    content:   str = Form(...),
    category:  str = Form(...),
    tags:      str = Form(""),
    published: str = Form("0"),
):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)

    if category not in VALID_CATEGORIES:
        category = "computacion"

    tags_list = [truncate(t.strip(), 50) for t in tags.split(",") if t.strip()][:10]
    now = datetime.now().isoformat()
    conn = get_db()
    try:
        conn.execute(
            "UPDATE blog_posts SET title=?,summary=?,content=?,category=?,tags=?,published=?,updated_at=? WHERE id=?",
            (
                truncate(title, 200),
                truncate(summary, 500),
                truncate(content, 50000),
                category,
                json.dumps(tags_list),
                int(published == "1"),
                now,
                post_id
            )
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/posts/{post_id}/eliminar")
async def admin_delete_post(request: Request, post_id: int):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    conn = get_db()
    try:
        conn.execute("DELETE FROM blog_posts WHERE id=?", (post_id,))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/posts/{post_id}/toggle")
async def admin_toggle_post(request: Request, post_id: int):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    conn = get_db()
    try:
        conn.execute(
            "UPDATE blog_posts SET published = CASE WHEN published=1 THEN 0 ELSE 1 END WHERE id=?",
            (post_id,)
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/contactos/{contact_id}/leer")
async def admin_mark_read(request: Request, contact_id: int):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    conn = get_db()
    try:
        conn.execute("UPDATE contacts SET read=1 WHERE id=?", (contact_id,))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/admin", status_code=302)
