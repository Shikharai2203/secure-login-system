from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secretkey"


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        failed_attempts INTEGER DEFAULT 0,
        lock_until REAL DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

init_db()


# ---------------- SECURITY LOG ----------------
def log_event(username, event):

    log = {
        "username": username,
        "event": event,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        with open("security_log.json","r") as f:
            data = json.load(f)
    except:
        data = []

    data.append(log)

    with open("security_log.json","w") as f:
        json.dump(data,f,indent=4)


# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        # Hash password
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (username,password) VALUES (?,?)",
                (username,hashed)
            )

            conn.commit()
            conn.close()

        except:
            return "Username already exists"

        # -------- JSON DEMO LOG --------
        log_entry = {
            "username": username,
            "password": password,
            "hashed_value": hashed,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        try:
            with open("password_log.json","r") as file:
                data = json.load(file)
        except:
            data = []

        data.append(log_entry)

        with open("password_log.json","w") as file:
            json.dump(data,file,indent=4)

        return redirect("/login")

    return render_template("register.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password,failed_attempts,lock_until FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        if not user:
            conn.close()
            return "User not found"

        stored_hash, attempts, lock_until = user
        current_time = datetime.now().timestamp()

        # Check if locked
        if lock_until and current_time < lock_until:
            conn.close()
            return "Account locked. Try again later."

        # Check password
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):

            cursor.execute(
                "UPDATE users SET failed_attempts=0, lock_until=0 WHERE username=?",
                (username,)
            )

            conn.commit()
            conn.close()

            session["user"] = username
            log_event(username,"Successful Login")

            return redirect("/dashboard")

        # Wrong password
        attempts += 1

        if attempts >= 3:

            lock_time = datetime.now().timestamp() + 300

            cursor.execute(
                "UPDATE users SET failed_attempts=?, lock_until=? WHERE username=?",
                (attempts,lock_time,username)
            )

            conn.commit()
            conn.close()

            log_event(username,"Account Locked")

            return "Account locked for 5 minutes"

        else:

            cursor.execute(
                "UPDATE users SET failed_attempts=? WHERE username=?",
                (attempts,username)
            )

            conn.commit()
            conn.close()

            log_event(username,"Failed Login")

            return f"Wrong password (Attempt {attempts}/3)"

    return render_template("login.html")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template("dashboard.html",user=session["user"])


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():

    user = session.get("user")

    session.clear()

    log_event(user,"Logout")

    return redirect("/login")


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)