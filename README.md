# Portfolio — Ezequiel Zamora

Web app con FastAPI + Jinja2 + SQLite.

---

## Correr localmente

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Abrir: http://localhost:8000  
Admin: http://localhost:8000/admin/login → usuario `ezequiel` / contraseña `admin1234`

---

## Deploy en Railway — Variables de entorno obligatorias

En Railway → tu proyecto → **Variables**, agregar:

| Variable         | Valor                                      |
|------------------|--------------------------------------------|
| `SECRET_KEY`     | Genera con: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_USER`     | Tu usuario admin (ej: `ezequiel`)          |
| `ADMIN_PASSWORD` | Tu contraseña admin segura                 |
| `PASSWORD_SALT`  | Texto aleatorio (ej: `mi-salt-secreto-42`) |

**Sin estas variables el admin usa credenciales por defecto — cámbialas antes de publicar.**

---

## Estructura

```
portfolio/
├── main.py           # App principal: rutas, BD, seguridad
├── requirements.txt
├── Procfile          # Para Railway
├── railway.toml
├── database/         # SQLite (se crea automáticamente)
├── static/
└── templates/
    ├── base.html
    ├── index.html
    ├── blog.html
    ├── post.html
    └── admin/
        ├── login.html
        ├── base_admin.html
        ├── dashboard.html
        └── post_form.html
```
