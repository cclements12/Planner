from flask import Flask, render_template

app = Flask(__name__)

#URL & page definitions
@app.route("/")
def main_page():
    '''URL definition for main page'''

    return render_template('main.html')