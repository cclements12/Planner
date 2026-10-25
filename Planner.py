from flask import Flask, render_template

import sqlite3

app = Flask(__name__)

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
@app.route("/")
def main_page():
    '''URL definition for main page'''

    return render_template('main.html')


