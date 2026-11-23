import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db, migrate
from . import models  # Register model metadata before initialization.
from .routes.auth import auth
from .routes.pages import pages
from .routes.api import api

try:
    from dotenv import load_dotenv
except ImportError:  # A minimal install can still launch; .env loading is optional at runtime.
    def load_dotenv(_path):
        return False


def create_app(test_config=None):
    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env")
    app = Flask(__name__, instance_relative_config=True)
    # On a laptop, keep the current SQLite file (and all existing student records).
    # On an internet host, set DATABASE_URL to a persistent PostgreSQL database.
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url.startswith("postgres://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
    elif database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
    if not database_url:
        database_url = f"sqlite:///{(Path(app.instance_path) / 'studyx_blue.sqlite3').as_posix()}"
    # SQLite supports the busy timeout; PostgreSQL doesn't accept that argument.
    engine_options = {"connect_args": {"timeout": 30}} if database_url.startswith("sqlite:") else {}
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("STUDYX_SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # SQLite normally gives up after 5 seconds if another connection is busy.
        # Keep this longer than a short-lived database editor read transaction.
        SQLALCHEMY_ENGINE_OPTIONS=engine_options,
        SQLALCHEMY_DATABASE_URI=database_url,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("STUDYX_COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
        DEBUG=os.environ.get("FLASK_DEBUG", "0") == "1",
        PORT=os.environ.get("PORT", "5000"),
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    migrate.init_app(app, db, directory=str(project_root / "migrations"))

    with app.app_context():
        if db.engine.dialect.name == "sqlite":
            # WAL lets the app write while a database browser reads. It does not
            # override another tool's uncommitted *write* transaction.
            try:
                with db.engine.connect() as connection:
                    mode = connection.exec_driver_sql("PRAGMA journal_mode").scalar()
                    if mode and mode.lower() != "wal":
                        mode = connection.exec_driver_sql("PRAGMA journal_mode=WAL").scalar()
                    if mode and mode.lower() not in ("wal", "memory"):
                        app.logger.warning("SQLite journal mode is %s, not WAL.", mode)
            except SQLAlchemyError:
                # DB Browser may have a pending transaction. Don't replace or
                # reset the existing database just to change its journal mode.
                app.logger.warning(
                    "Couldn't enable SQLite WAL. Commit or rollback pending DB Browser "
                    "changes and disconnect its database connection."
                )
        db.create_all()

    @app.before_request
    def csrf_guard():
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("_csrf_token")
        if not expected or not supplied or not secrets.compare_digest(supplied, expected):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Your session security token expired. Refresh and try again."}), 400
            return render_template("error.html", title="Security check expired",
                                   message="Refresh this page and submit the form again."), 400
        return None

    @app.before_request
    def require_account():
        endpoint = request.endpoint or ""
        if endpoint == "static" or endpoint.startswith("auth."):
            return None
        if session.get("user_id"):
            return None
        if request.path == "/api/contact" and request.method == "POST":
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "Please sign in to continue."}), 401
        if endpoint.startswith("pages.public_") or endpoint == "pages.service_worker":
            return None
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))

    @app.context_processor
    def inject_shared_context():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        admin_email = os.environ.get("STUDYX_CONTACT_ADMIN_EMAIL", "").strip().lower()
        logged_user = db.session.get(models.User, session["user_id"]) if session.get("user_id") and admin_email else None
        return {
            "csrf_token": session["_csrf_token"],
            "theme_mode": session.get("theme_mode", "light"),
            "student_name": session.get("display_name", "Student"),
            "is_contact_admin": bool(logged_user and logged_user.email.lower() == admin_email),
        }

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", title="Page not found",
                               message="That page isn't part of this study space."), 404

    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        db.session.rollback()
        app.logger.exception("Database request failed", exc_info=error)
        if request.path.startswith("/api/"):
            return jsonify({"error": "We couldn't save that just now. Please try again."}), 500
        return render_template("error.html", title="Couldn't load this page",
                               message="Your saved study data is safe. Refresh the page to try again."), 500

    app.register_blueprint(pages)
    app.register_blueprint(auth)
    app.register_blueprint(api, url_prefix="/api")
    return app
