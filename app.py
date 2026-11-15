"""
Secure IT Helpdesk Portal
A small Flask + SQLite web app where users report IT issues,
track their tickets and read solutions to common problems.
Admins get a dashboard to manage every ticket.
"""

import os
import secrets
import sqlite3
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Read the secret key from an environment variable. Fall back to a random one for local testing.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "helpdesk.db")
STATUSES = ["Open", "In Progress", "Resolved"]
PRIORITIES = ["Low", "Medium", "High"]
CATEGORIES = ["Hardware", "Software", "Network", "Account / Password", "Other"]


# ---------------- Database helpers ----------------

def get_db():
    """Open one database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # lets us use row["column_name"]
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the tables and add a default admin and some FAQs."""
    db = sqlite3.connect(DATABASE)
    with open(os.path.join(BASE_DIR, "schema.sql")) as f:
        db.executescript(f.read())

    # Create the default admin account if it does not exist yet
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin123!")
    if db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone() is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            ("admin", generate_password_hash(admin_password, method="pbkdf2:sha256")),
        )

    # Add a few starter FAQs if the table is empty
    if db.execute("SELECT COUNT(*) FROM faqs").fetchone()[0] == 0:
        starter_faqs = [
            ("I forgot my password", "Contact the IT team by phone or in person. They will check your identity and reset it for you."),
            ("Wi-Fi keeps disconnecting", "Forget the network, reconnect, and restart your device. If it still drops, raise a Network ticket."),
            ("Printer says offline", "Check the printer is switched on and connected to the same network, then remove and re-add it."),
            ("Computer is running slowly", "Restart it, close unused programs and make sure updates are installed."),
        ]
        db.executemany("INSERT INTO faqs (question, answer) VALUES (?, ?)", starter_faqs)

    db.commit()
    db.close()


# ---------------- Security helpers ----------------

def login_required(view):
    """Only let logged-in users see this page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Only let admins see this page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return login_required(wrapped)


@app.before_request
def check_csrf():
    """Simple CSRF protection: every POST form must send back the token stored in the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            abort(400)


@app.context_processor
def add_csrf_token():
    """Make csrf_token available in every template."""
    return {"csrf_token": session.get("csrf_token", "")}


# ---------------- Auth routes ----------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("admin_dashboard" if session["role"] == "admin" else "my_tickets"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must be at least 3 characters.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                    (username, generate_password_hash(password, method="pbkdf2:sha256")),
                )
                db.commit()
                flash("Account created. You can now log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # Same message for wrong username or wrong password, so attackers can't guess usernames
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# ---------------- User routes ----------------

@app.route("/tickets")
@login_required
def my_tickets():
    tickets = get_db().execute(
        "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at DESC", (session["user_id"],)
    ).fetchall()
    return render_template("my_tickets.html", tickets=tickets)


@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def new_ticket():
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        category = request.form["category"]
        priority = request.form["priority"]

        if not title or not description:
            flash("Title and description are required.")
        elif category not in CATEGORIES or priority not in PRIORITIES:
            flash("Invalid category or priority.")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO tickets (user_id, title, description, category, priority) VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], title, description, category, priority),
            )
            db.commit()
            flash("Ticket submitted.")
            return redirect(url_for("my_tickets"))

    return render_template("new_ticket.html", categories=CATEGORIES, priorities=PRIORITIES)


@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):
    db = get_db()
    ticket = db.execute(
        "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.user_id = users.id WHERE tickets.id = ?",
        (ticket_id,),
    ).fetchone()

    if ticket is None:
        abort(404)
    # A normal user can only see their own tickets
    if session["role"] != "admin" and ticket["user_id"] != session["user_id"]:
        abort(403)

    if request.method == "POST":
        message = request.form["message"].strip()
        if message:
            db.execute(
                "INSERT INTO comments (ticket_id, user_id, message) VALUES (?, ?, ?)",
                (ticket_id, session["user_id"], message),
            )
        # Only admins can change the status
        new_status = request.form.get("status")
        if session["role"] == "admin" and new_status in STATUSES:
            db.execute("UPDATE tickets SET status = ? WHERE id = ?", (new_status, ticket_id))
        db.commit()
        flash("Ticket updated.")
        return redirect(url_for("view_ticket", ticket_id=ticket_id))

    comments = db.execute(
        "SELECT comments.*, users.username, users.role FROM comments JOIN users ON comments.user_id = users.id "
        "WHERE ticket_id = ? ORDER BY comments.created_at",
        (ticket_id,),
    ).fetchall()
    return render_template("ticket.html", ticket=ticket, comments=comments, statuses=STATUSES)


@app.route("/faq")
def faq():
    faqs = get_db().execute("SELECT * FROM faqs ORDER BY id").fetchall()
    return render_template("faq.html", faqs=faqs)


# ---------------- Admin routes ----------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    status_filter = request.args.get("status", "")

    # Count tickets in each status for the summary cards
    counts = {status: 0 for status in STATUSES}
    for row in db.execute("SELECT status, COUNT(*) AS total FROM tickets GROUP BY status"):
        counts[row["status"]] = row["total"]

    query = "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.user_id = users.id"
    params = ()
    if status_filter in STATUSES:
        query += " WHERE status = ?"
        params = (status_filter,)
    query += " ORDER BY created_at DESC"
    tickets = db.execute(query, params).fetchall()

    user_count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'user'").fetchone()[0]
    return render_template("admin.html", tickets=tickets, counts=counts, user_count=user_count,
                           statuses=STATUSES, status_filter=status_filter)


@app.route("/admin/faq", methods=["POST"])
@admin_required
def add_faq():
    question = request.form["question"].strip()
    answer = request.form["answer"].strip()
    if question and answer:
        db = get_db()
        db.execute("INSERT INTO faqs (question, answer) VALUES (?, ?)", (question, answer))
        db.commit()
        flash("FAQ added.")
    return redirect(url_for("faq"))


@app.route("/admin/faq/<int:faq_id>/delete", methods=["POST"])
@admin_required
def delete_faq(faq_id):
    db = get_db()
    db.execute("DELETE FROM faqs WHERE id = ?", (faq_id,))
    db.commit()
    flash("FAQ deleted.")
    return redirect(url_for("faq"))


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found."), 404


if __name__ == "__main__":
    init_db()
    app.run(port=5001, debug=False)
