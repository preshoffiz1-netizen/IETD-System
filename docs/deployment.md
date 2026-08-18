# Deployment

## Do not use the Flask development server in production

`python run.py` (Flask's built-in dev server) is for local development only. For anything
resembling a real deployment, use `wsgi.py` behind a production WSGI server:

```bash
pip install -r requirements.txt
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app
```

`wsgi.py` builds the app with `create_app("production")`, which sets `SESSION_COOKIE_SECURE`
and `REMEMBER_COOKIE_SECURE` to `True` (requires HTTPS) and disables debug mode.

## Environment configuration

Set real values for at least:

- `SECRET_KEY` - a long random value, different from development.
- `ENCRYPTION_KEY` - a Fernet key; losing this makes all stored mailbox credentials
  unrecoverable, so back it up securely (a secrets manager, not source control).
- `DATABASE_URL` - point at PostgreSQL for anything beyond a single-user local demo, e.g.
  `postgresql+psycopg2://user:password@host:5432/ietds`. No code changes are required - the
  data layer was built against the SQLAlchemy ORM specifically so this swap is a one-line
  `.env` change (Section 46).
- `SESSION_COOKIE_SECURE=1` (only meaningful behind HTTPS).
- Gmail OAuth credentials and redirect URI, updated to your real domain.

## Reverse proxy

Run gunicorn behind nginx (or similar) for TLS termination, static file serving, and request
buffering. A minimal nginx `location` block:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`app/__init__.py` already sets `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, and a `Content-Security-Policy` on every response, and adds
`Strict-Transport-Security` automatically once `SESSION_COOKIE_SECURE` is enabled.

## Background scanning in production

The in-process APScheduler approach (`app/services/scheduler.py`) works fine behind a single
gunicorn worker process. If you scale to multiple worker processes/instances, either:

- Pin background scanning to a single dedicated process (e.g. a separate gunicorn instance
  with `--workers 1` just for scanning, fronted by nothing), or
- Replace `scheduler.py` with a Celery + Redis worker (the module boundary was designed for
  exactly this swap - nothing outside `scheduler.py` needs to change).

## Database migrations

```bash
flask --app wsgi:app db upgrade
```

Run this as part of your deployment process once you've moved past `db.create_all()`-on-boot
for local development.

## Backups

Back up the database and the `ENCRYPTION_KEY` together - a database backup without the
matching encryption key is useless for recovering mailbox credentials, and vice versa.
