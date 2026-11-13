import json
import logging
import os
import re
import secrets
import string
import sqlite3
import time
from datetime import date, datetime
from functools import wraps
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)
from passlib.hash import sha256_crypt

import Prompt

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


#DATABASE HELPERS

def create_tables(cursor):
    """Create the task, project member and task user tables if missing."""

    # Table associated with task card data
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

    # PROPOSED: links a user to a project (group_id is the project key)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_members (
            group_id TEXT NOT NULL,
            username TEXT NOT NULL COLLATE NOCASE,
            role TEXT NOT NULL DEFAULT 'member',
            added_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, username)
        )
    """)

    # PROPOSED: additional users on a card; rows go when the card is deleted
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS task_users (
            task_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            username TEXT NOT NULL COLLATE NOCASE,
            added_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (task_id, username)
        )
    """)


def get_db():
    """Open planner_data.db with named columns, foreign keys on, tables present."""

    sql_database = sqlite3.connect("planner_data.db")
    sql_database.row_factory = sqlite3.Row
    sql_database.execute("PRAGMA foreign_keys = ON")
    create_tables(sql_database)

    return sql_database


# (form field name, label) for the TEXT NOT NULL columns
REQUIRED_TASK_FIELDS = [
    ("task_name", "Task name"),
    ("group_id", "Group ID"),
    ("task_status", "Status"),
    ("task_priority", "Priority (text)"),
    ("task_description", "Description"),
    ("task_assigned_user", "Assigned user"),
    ("task_notes", "Notes"),
]


def parse_task_form(form):
    """Return (task dict, extra usernames, error messages) from submitted form data."""

    errors = []
    task = {}

    for field, label in REQUIRED_TASK_FIELDS:

        task[field] = form.get(field, "").strip()

        if not task[field]:

            errors.append(f"{label} is required.")

    # Optional dates are stored as TEXT (YYYY-MM-DD from the date inputs)
    for field in ("start_date", "due_date"):

        value = form.get(field, "").strip()

        if value:

            try:

                datetime.strptime(value, "%Y-%m-%d")

            except ValueError:

                errors.append(f"{field.replace('_', ' ').capitalize()} must be a valid date.")

        task[field] = value or None

    if task["start_date"] and task["due_date"] and not errors \
            and task["due_date"] < task["start_date"]:

        errors.append("Due date cannot be before the start date.")

    try:

        task["priority"] = int(form.get("priority", "").strip() or 1)

    except ValueError:

        task["priority"] = 1
        errors.append("Priority (number) must be a whole number.")

    # Unchecked checkboxes are not submitted at all
    task["completed"] = 1 if form.get("completed") else 0

    extra_users = []

    for name in form.get("task_users", "").split(","):

        name = name.strip()

        if not name:

            continue

        if not USERNAME_PATTERN.match(name):

            errors.append(f"'{name}' is not a valid username.")

        elif name.lower() not in (user.lower() for user in extra_users):

            extra_users.append(name)

    return task, extra_users, errors


def save_task_users(sql_database, task_id, task, extra_users):
    """Replace a card's extra users and make sure everyone is on the project."""

    sql_database.execute("DELETE FROM task_users WHERE task_id = ?", (task_id,))

    for name in extra_users:

        sql_database.execute(
            "INSERT OR IGNORE INTO task_users (task_id, username) VALUES (?, ?)",
            (task_id, name))

    # Assigning a user to a card also adds them to the card's project
    everyone = extra_users + [task["task_assigned_user"]]

    for name in everyone:

        if USERNAME_PATTERN.match(name) and name.lower() != "unassigned":

            sql_database.execute(
                "INSERT OR IGNORE INTO project_members (group_id, username) VALUES (?, ?)",
                (task["group_id"], name))


#TESTING APP ROUTE! initializes DB
@app.route("/initialize")
def init_db():

    #Creates variable for connected database
    sql_database = sqlite3.connect("planner_data.db")

    cursor = sql_database.cursor()

    # Create tables associated with task card data and project users
    create_tables(cursor)


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
    '''URL definition for main page: lists every task card in order'''

    sql_database = sqlite3.connect("planner_data.db")
    sql_database.row_factory = sqlite3.Row

    cursor = sql_database.cursor()

    try:
        # Tasks listed in the order they were created (lowest id first)
        cursor.execute("SELECT * FROM messages ORDER BY id ASC")
        tasks = cursor.fetchall()
    except sqlite3.OperationalError:
        # Table not created yet (visit /initialize first)
        tasks = []
    finally:
        sql_database.close()

    return render_template('main.html', tasks=tasks)


@app.route("/tasks/new")
@login_required
def new_task_page():
    '''Blank task form'''

    return render_template("task_form.html", task={"priority": 1}, extra_users="",
                           form_action=url_for("create_task"), heading="Add Task")


@app.route("/tasks", methods=["POST"])
@login_required
def create_task():
    '''Insert a new task card'''

    task, extra_users, errors = parse_task_form(request.form)

    if errors:

        for error in errors:

            flash(error)

        return render_template("task_form.html", task=task,
                               extra_users=", ".join(extra_users),
                               form_action=url_for("create_task"), heading="Add Task")

    sql_database = get_db()

    cursor = sql_database.execute(
        """
        INSERT INTO messages
            (task_name, group_id, task_status, task_priority, task_description,
             task_assigned_user, task_notes, start_date, due_date, priority, completed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (task["task_name"], task["group_id"], task["task_status"], task["task_priority"],
         task["task_description"], task["task_assigned_user"], task["task_notes"],
         task["start_date"], task["due_date"], task["priority"], task["completed"]))

    save_task_users(sql_database, cursor.lastrowid, task, extra_users)

    sql_database.commit()
    sql_database.close()

    flash("Task created.")
    return redirect(url_for("main_page"))


@app.route("/tasks/<int:task_id>/edit")
@login_required
def edit_task_page(task_id):
    '''Task form pre-filled with an existing task'''

    sql_database = get_db()

    row = sql_database.execute("SELECT * FROM messages WHERE id = ?", (task_id,)).fetchone()

    users = sql_database.execute(
        "SELECT username FROM task_users WHERE task_id = ? ORDER BY username",
        (task_id,)).fetchall()

    sql_database.close()

    if row is None:

        flash("That task does not exist.")
        return redirect(url_for("main_page"))

    return render_template("task_form.html", task=dict(row),
                           extra_users=", ".join(user["username"] for user in users),
                           form_action=url_for("update_task", task_id=task_id),
                           heading=f"Edit Task #{task_id}")


@app.route("/tasks/<int:task_id>", methods=["POST"])
@login_required
def update_task(task_id):
    '''Save changes to an existing task card'''

    task, extra_users, errors = parse_task_form(request.form)

    if errors:

        for error in errors:

            flash(error)

        return render_template("task_form.html", task={**task, "id": task_id},
                               extra_users=", ".join(extra_users),
                               form_action=url_for("update_task", task_id=task_id),
                               heading=f"Edit Task #{task_id}")

    sql_database = get_db()

    cursor = sql_database.execute(
        """
        UPDATE messages SET
            task_name = ?, group_id = ?, task_status = ?, task_priority = ?,
            task_description = ?, task_assigned_user = ?, task_notes = ?,
            start_date = ?, due_date = ?, priority = ?, completed = ?
        WHERE id = ?
        """,
        (task["task_name"], task["group_id"], task["task_status"], task["task_priority"],
         task["task_description"], task["task_assigned_user"], task["task_notes"],
         task["start_date"], task["due_date"], task["priority"], task["completed"],
         task_id))

    if cursor.rowcount == 0:

        sql_database.close()
        flash("That task does not exist.")
        return redirect(url_for("main_page"))

    save_task_users(sql_database, task_id, task, extra_users)

    sql_database.commit()
    sql_database.close()

    flash("Task updated.")
    return redirect(url_for("main_page"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    '''Delete a task card (POST only, so a link or crawler can never delete one)'''

    sql_database = get_db()

    # get_db() turns foreign keys on, so the card's task_users rows cascade away
    cursor = sql_database.execute("DELETE FROM messages WHERE id = ?", (task_id,))

    sql_database.commit()
    deleted = cursor.rowcount
    sql_database.close()

    flash("Task deleted." if deleted else "That task does not exist.")
    return redirect(url_for("main_page"))


#AI PROJECT PLANS

GROUP_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

PLAN_COOLDOWN_SECONDS = 15   # minimum gap between AI requests from one user
_last_plan_request = {}      # username -> time of last request (per worker process)


def group_exists(sql_database, group_id):
    """Return True if any task or member already uses this group_id (ignoring case)."""

    row = sql_database.execute(
        """
        SELECT 1 FROM messages WHERE lower(group_id) = lower(?)
        UNION
        SELECT 1 FROM project_members WHERE lower(group_id) = lower(?)
        """,
        (group_id, group_id)).fetchone()

    return row is not None


def unique_group_id(sql_database, project_name):
    """Build a group_id from the project name, adding _2, _3... if it is taken."""

    base = re.sub(r"[^a-z0-9]+", "_", project_name.lower()).strip("_")[:34] or "project"
    candidate = base
    number = 2

    while group_exists(sql_database, candidate):

        candidate = f"{base}_{number}"
        number += 1

    return candidate


def parse_start_date(value):
    """Return a date from a YYYY-MM-DD string, or today if blank. None if invalid."""

    value = (value or "").strip()

    if not value:

        return date.today()

    try:

        return datetime.strptime(value, "%Y-%m-%d").date()

    except ValueError:

        return None


def render_plan_preview(items, project_name, project_start, group_id, selected=None):
    """Show the generated plan so it can be reviewed before anything is saved."""

    return render_template(
        "plan_preview.html",
        rows=Prompt.to_task_rows(items, project_start),
        plan_json=json.dumps(items),
        project_name=project_name,
        project_start=project_start.isoformat(),
        group_id=group_id,
        selected=selected)


@app.route("/plan/new")
@login_required
def new_plan_page():
    '''Form describing the project the AI should plan'''

    return render_template("plan_form.html", form={}, today=date.today().isoformat())


@app.route("/plan/generate", methods=["POST"])
@login_required
def generate_plan():
    '''Ask the AI for a plan and show it for review (nothing is saved yet)'''

    form = {
        "project_name": request.form.get("project_name", "").strip(),
        "description": request.form.get("description", "").strip(),
        "start_date": request.form.get("start_date", "").strip(),
        "weeks": request.form.get("weeks", "").strip(),
    }

    errors = []

    if not form["project_name"] or len(form["project_name"]) > 80:

        errors.append("Project name is required (80 characters at most).")

    if not form["description"] or len(form["description"]) > 3000:

        errors.append("Project description is required (3000 characters at most).")

    project_start = parse_start_date(form["start_date"])

    if project_start is None:

        errors.append("Start date must be a valid date.")

    weeks = None

    if form["weeks"]:

        if form["weeks"].isdigit() and 1 <= int(form["weeks"]) <= 104:

            weeks = int(form["weeks"])

        else:

            errors.append("Target length must be a whole number of weeks from 1 to 104.")

    # Each request costs money, so slow down repeated clicks from one user
    wait = PLAN_COOLDOWN_SECONDS - (time.monotonic() - _last_plan_request.get(session["username"], -1e9))

    if not errors and wait > 0:

        errors.append(f"Please wait {int(wait) + 1} seconds before generating another plan.")

    if not errors:

        _last_plan_request[session["username"]] = time.monotonic()

        try:

            items = Prompt.generate_project_plan(form["project_name"], form["description"], weeks)

        except Prompt.GeminiError as error:

            errors.append(str(error))

    if errors:

        for error in errors:

            flash(error)

        return render_template("plan_form.html", form=form, today=date.today().isoformat())

    sql_database = get_db()
    group_id = unique_group_id(sql_database, form["project_name"])
    sql_database.close()

    return render_plan_preview(items, form["project_name"], project_start, group_id)


@app.route("/plan/save", methods=["POST"])
@login_required
def save_plan():
    '''Save the reviewed plan as tasks under its own new group_id'''

    group_id = request.form.get("group_id", "").strip()
    project_name = request.form.get("project_name", "").strip()
    project_start = parse_start_date(request.form.get("project_start"))

    # The plan travels in a hidden field, so it is validated again here
    try:

        items = Prompt.sanitize_items(json.loads(request.form.get("plan_json", "")))

    except ValueError:

        flash("That plan could not be read. Please generate it again.")
        return redirect(url_for("new_plan_page"))

    if project_start is None:

        flash("The project start date was not valid. Please generate the plan again.")
        return redirect(url_for("new_plan_page"))

    selected = set()

    for value in request.form.getlist("include"):

        if value.isdigit():

            selected.add(int(value))

    chosen = [item for index, item in enumerate(items) if index in selected]

    problem = None

    if not GROUP_ID_PATTERN.match(group_id):

        problem = "Group ID must be 1-40 characters: letters, numbers, hyphens or underscores."

    elif not chosen:

        problem = "Select at least one task to save."

    sql_database = get_db()

    if problem is None and group_exists(sql_database, group_id):

        problem = f"The group ID '{group_id}' is already in use. Choose a different one."

    if problem:

        sql_database.close()
        flash(problem)
        return render_plan_preview(items, project_name, project_start, group_id, selected)

    # Tasks are inserted in plan order, so ids (and the task list) keep that order
    for row in Prompt.to_task_rows(chosen, project_start):

        sql_database.execute(
            """
            INSERT INTO messages
                (task_name, group_id, task_status, task_priority, task_description,
                 task_assigned_user, task_notes, start_date, due_date, priority, completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (row["task_name"], group_id, row["task_status"], row["task_priority"],
             row["task_description"], row["task_assigned_user"], row["task_notes"],
             row["start_date"], row["due_date"], row["priority"], row["completed"]))

    # The person who generated the plan owns the new project
    sql_database.execute(
        "INSERT INTO project_members (group_id, username, role) VALUES (?, ?, 'owner')",
        (group_id, session["username"]))

    sql_database.commit()
    sql_database.close()

    flash(f"Saved {len(chosen)} tasks to project '{group_id}'.")
    return redirect(url_for("main_page"))


@app.route("/project_members", methods=["POST"])
@login_required
def add_project_member():
    '''Add a user to a project, or update their role if already a member'''

    group_id = request.form.get("group_id", "").strip()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "").strip() or "member"

    if not group_id:

        flash("Group ID is required.")

    elif not USERNAME_PATTERN.match(username):

        flash("Username must be 3-20 characters: letters, numbers or underscores only.")

    else:

        sql_database = get_db()

        sql_database.execute(
            """
            INSERT INTO project_members (group_id, username, role) VALUES (?, ?, ?)
            ON CONFLICT(group_id, username) DO UPDATE SET role = excluded.role
            """,
            (group_id, username, role))

        sql_database.commit()
        sql_database.close()

        flash(f"{username} is now a {role} of {group_id}.")

    return redirect(url_for("new_task_page"))


