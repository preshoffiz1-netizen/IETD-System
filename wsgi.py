"""
Production WSGI entry point.

Run with a real WSGI server, e.g.:
    gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app

Do NOT use `flask run` / the Flask development server in production
(Section 70).
"""

from app import create_app

app = create_app("production")

if __name__ == "__main__":  # pragma: no cover
    app.run()
