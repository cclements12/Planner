import logging
import os
import re
import secrets
import string
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)
from passlib.hash import sha256_crypt

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

#Path to users
USER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),"users.txt")

#username
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")

#Path to CommonPasswords
COMMON_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),"CommonPassword.txt")

MIN_COMMON_LENGTH = 5

#login failure captured
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),"failed_logins.log")

LOG_FORMAT = logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

FAILED_LOGIN_LOG = logging.getLogger("failed_logins")
FAILED_LOGIN_LOG.setLevel(logging.WARNING)

if not FAILED_LOGIN_LOG.handlers:  # avoid duplicate lines if re-imported
    _handler = logging.FileHandler(LOG_FILE, encoding="utf-8", delay=True)
    _handler.setFormatter(LOG_FORMAT)
    FAILED_LOGIN_LOG.addHandler(_handler)


#conditional checks for failed password complexity
def check_password_complexity(password):
    """Return a list of unmet password rules (an empty list means valid)."""
    problems = []
    if len(password) < 12:
        problems.append("be at least 12 characters long")
    if not any(char.isupper() for char in password):
        problems.append("contain at least 1 uppercase letter")
    if not any(char.islower() for char in password):
        problems.append("contain at least 1 lowercase letter")
    if not any(char.isdigit() for char in password):
        problems.append("contain at least 1 number")
    if not any(char in string.punctuation for char in password):
        problems.append("contain at least 1 special character")
    return problems

#loads list of common passwords from COMMON_FILE variable
def load_common_passwords():
    """Return the common passwords (lowercase) long enough to search for."""

    with open(COMMON_FILE, encoding="utf-8-sig") as common_file:

        words = (line.strip().lower() for line in common_file)

        return [word for word in words if len(word) >= MIN_COMMON_LENGTH]

#required after declaring load_common_passwords
COMMON_PASSWORDS = load_common_passwords()

def is_common_password(password):
    """Return True if the password is built from a common password."""
    lowered = password.lower()

    return any(word in lowered for word in COMMON_PASSWORDS)

def password_errors(password):
    """Return error messages for prospective password. Applies the length/complexity rules """

    errors = []
    problems = check_password_complexity(password)

    if problems:

        errors.append("Password must " + ", ".join(problems) + ".")

    if is_common_password(password):

        errors.append("That password uses commonly-used, expected," +
        " or compromised strings. Please try again.")

    return errors

def log_failed_login(username):
    """Write a failed login to log file"""

    FAILED_LOGIN_LOG.warning("Login Failed - IP Address: %s - User: %r",
    request.remote_addr, username[:50])


def load_users():
    """Read the user file and return a dict."""
    users = {}
    if os.path.exists(USER_FILE):

        with open(USER_FILE, encoding="utf-8") as user_file:

            for line in user_file:

                line = line.strip()

                if line:

                    name, pw_hash = line.split(":", 1)
                    users[name] = pw_hash

    return users


def save_user(username, pw_hash):
    """Append a new username and password hash to the user file."""
    with open(USER_FILE, "a", encoding="utf-8") as user_file:

        user_file.write(f"{username}:{pw_hash}\n")


def save_users(users):
    """Overwrite the user file with every {username: password_hash} pair."""

    with open(USER_FILE, "w", encoding="utf-8") as user_file:

        for name, pw_hash in users.items():

            user_file.write(f"{name}:{pw_hash}\n")


def login_required(view):
    """Decorator: send visitors who are not logged in to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):

        if "username" not in session:

            flash("You must be logged in to view this page.")
            return redirect(url_for("login_page"))

        return view(*args, **kwargs)
    return wrapped


def validate_registration(username, password, confirm):
    """Return a list of error messages for a registration (empty = valid)."""
    errors = []
    if not USERNAME_PATTERN.match(username):

        errors.append("Username must be 3-20 characters: letters, numbers or underscores only.")

    elif username.lower() in (name.lower() for name in load_users()):

        errors.append("That username is already taken.")

    if password != confirm:

        errors.append("Passwords do not match.")

    errors.extend(password_errors(password))
    return errors


def credentials_valid(username, password):
    """Return True if the username exists and the password matches."""
    pw_hash = load_users().get(username)
    return bool(pw_hash) and sha256_crypt.verify(password, pw_hash)


def validate_reset(username, old_password, new_password, confirm):
    """Return a list of error messages for a password reset (empty = valid)."""

    if not credentials_valid(username, old_password):

        return ["Invalid username or old password."]

    errors = []
    if new_password != confirm:

        errors.append("New passwords do not match.")

    if new_password == old_password:

        errors.append("New password must be different from the old password.")

    errors.extend(password_errors(new_password))

    return errors

#APP ROUTES / DEFINES PAGES FOR APP

@app.route("/register", methods=["GET", "POST"])
def register_page():
    '''URL definition for the registration page'''
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = validate_registration(username, password, confirm)
        for error in errors:
            flash(error)
        if not errors:
            save_user(username, sha256_crypt.hash(password))
            flash("Registration successful. Please log in.")
            return redirect(url_for("login_page"))
    return render_template("pageregister.html", currentTime=datetime.now())


@app.route("/", methods=["GET", "POST"])
def login_page():
    '''URL definition for login page'''
    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if credentials_valid(username, password):

            session.clear()
            session["username"] = username
            return redirect(url_for("main_page"))

        log_failed_login(username)

        # Same message for a bad username or bad password on purpose
        flash("Invalid username or password.")
    return render_template("pagelogin.html", currentTime=datetime.now())


@app.route("/reset", methods=["GET", "POST"])
def reset_page():
    '''URL definition for the password reset page'''

    if request.method == "POST":

        username = request.form.get("username", "")
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm", "")

        errors = validate_reset(username, old_password, new_password, confirm)
        for error in errors:

            flash(error)

        if not errors:

            users = load_users()
            users[username] = sha256_crypt.hash(new_password)
            save_users(users)
            flash("Password updated. Please log in with your new password.")
            return redirect(url_for("login_page"))

    return render_template("pagereset.html", currentTime=datetime.now())


@app.route("/logout")
def logout_page():
    '''Clear the session and return to the login page'''
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login_page"))


#TESTING APP ROUTE! initializes DB
@app.route("/initialize")
def init_db():

    #Creates variable for connected database
    sql_database = sqlite3.connect("planner_data.db")

    cursor = sql_database.cursor()

    # Create table associated with task card data. record details pulled from planner_data.db
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT NOT NULL,
            group_id TEXT NOT NULL,
            task_status TEXT NOT NULL,
            task_priority TEXT NOT NULL,
            task_description TEXT NOT NULL,
            task_assigned_user TEXT NOT NULL,
            task_notes TEXT NOT NULL,
            start_date TEXT,
            due_date TEXT,
            priority INTEGER DEFAULT 1,
            completed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # Insert a record into planner_data.db with test data
    cursor.execute(
    """
    INSERT INTO messages
        (task_name, group_id, task_status, task_priority,
         task_description, task_assigned_user, task_notes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
    ("Task Name 01", "group_1", "Not Started", "Medium",
     "Sample description", "unassigned", "sample notes")
)

    #close and save database data

    sql_database.commit()
    sql_database.close()
    return "Database initialized!"

#TESTING APP ROUTE! app route to load message data from database
@app.route("/messages")
def get_messages():

    #Creates variable for connected database
    sql_database = sqlite3.connect("planner_data.db")

    cursor = sql_database.cursor()

    #Selects all data from database and prints it
    cursor.execute("SELECT * FROM messages")
    rows = cursor.fetchall()
    sql_database.close()
    return str(rows)

#URL & page definitions
@app.route("/main")
def main_page():
    '''URL definition for main page'''

    return render_template('main.html')


