"""
Local development entry point.

    python run.py

Uses Flask's built-in dev server, which is fine for local development only.
For anything resembling production, use `wsgi.py` behind gunicorn (Section 70).
"""

import os

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=app.config.get("DEBUG", True))
