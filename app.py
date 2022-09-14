import os
from datetime import datetime
from xml.sax.handler import feature_external_ges
from zoneinfo import ZoneInfo
from dotenv import load_dotenv

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helper import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
conn = sqlite3.connect("finance.db", check_same_thread=False)
db = conn.cursor()

def configure():
    load_dotenv()

configure()
# Make sure API key is set
if not os.getenv("api_key"):
    raise RuntimeError("API_KEY not set")

db.execute("""CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT NOT NULL,
                hash TEXT NOT NULL,
                cash NUMERIC NOT NULL DEFAULT 10000.00)""")

db.execute("""CREATE TABLE IF NOT EXISTS owned_stocks
                (stock_id INTEGER, 
                stock TEXT NOT NULL, 
                name TEXT NOT NULL, 
                shares NUMBER NOT NULL, 
                price_per_stock NUMERIC NOT NULL, 
                total NUMERIC NOT NULL, 
                FOREIGN KEY(stock_id) 
                REFERENCES users(id))""")


db.execute("""CREATE TABLE IF NOT EXISTS history
                (history_id INTEGER, 
                status TEXT NOT NULL, 
                stock TEXT NOT NULL, 
                shares NUMBER NOT NULL, 
                time TEXT, 
                FOREIGN KEY(history_id) 
                REFERENCES users(id))""")
conn.commit()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/landing")
def landing():
    return render_template("landing.html")
    

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks if logged in, else show landing page"""
    row_before = db.execute("SELECT stock, name, shares, price_per_stock, total FROM owned_stocks WHERE stock_id=?", (session["user_id"],)).fetchall()
    total_cash = db.execute("SELECT cash FROM users WHERE id=?", (session["user_id"],)).fetchall()
    total = float(total_cash[0][0])
    # update with live stock info
    for stock in row_before:
        db.execute("UPDATE owned_stocks SET price_per_stock=?, total=? WHERE stock_id=?",
            (usd(lookup(stock[0])["price"]), usd(stock[2]*lookup(stock[0])["price"]), session["user_id"]))

        total += float(stock[2]) * lookup(stock[0])["price"]

    row_after = db.execute("SELECT stock, name, shares, price_per_stock, total FROM owned_stocks WHERE stock_id=?", (session["user_id"],)).fetchall()
    conn.commit()
    return render_template("index.html", row_after=row_after, total_cash=usd(total_cash[0][0]), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        share_amount = request.form.get("shares")
        if not symbol:
            return apology("symbol required", 400)
        if lookup(symbol) == None:
            return apology("invalid stock entry", 400)
        if not share_amount or int(share_amount) <= 0:
            return apology("invalid share input", 400)

        user_balance = db.execute("SELECT cash FROM users WHERE id=?", (session["user_id"],)).fetchall()
        total_price = lookup(symbol)["price"] * float(share_amount)

        if user_balance[0][0] - total_price < 0:
            return apology("insufficient funds")

        if db.execute("SELECT * FROM owned_stocks WHERE stock=?", (symbol,)).fetchall():
            current_shares = db.execute("SELECT shares FROM owned_stocks WHERE stock=?", (symbol,)).fetchall()
            db.execute("UPDATE owned_stocks SET shares=? WHERE stock=?", (share_amount + current_shares[0][0], symbol)).fetchall()
        else:
            db.execute("INSERT INTO owned_stocks(stock_id, stock, name, shares, price_per_stock, total) VALUES(?, ?, ?, ?, ?, ?)",
                    (session["user_id"], symbol, lookup(symbol)["name"], share_amount, lookup(symbol)["price"], usd(total_price)))

        db.execute("UPDATE users SET cash=? WHERE id=?", (user_balance[0][0] - total_price, session["user_id"]))

        db.execute("INSERT INTO history(history_id, status, stock, shares, time) VALUES(?, ?, ?, ?, ?)",
            (session["user_id"], "Buy", symbol, share_amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history") # default method is get
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM history WHERE history_id=?", (session["user_id"],)).fetchall()
    rows.reverse()
    return render_template("history.html", rows=rows)


@app.route("/clear_history")
@login_required
def clear_history():
    """Allow user to clear buy and sell history"""
    db.execute("DELETE FROM history WHERE history_id=?", (session["user_id"],))
    return redirect("/history")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username=?", (request.form.get("username"),)).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        conn.commit()
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
    

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allows user to change their current password"""
    if request.method == "POST":
        current_pw = request.form.get("current")
        new_pw = request.form.get("new")

        rows = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchall()
        if not current_pw or not check_password_hash(rows[0][2], current_pw):
            return apology("password incorrect", 403)
        if not new_pw or not request.form.get("new_confirm"):
            return apology("input new password", 403)
        if new_pw != request.form.get("new_confirm"):
            return apology("passwords do not match", 403)

        db.execute("UPDATE users SET hash=? WHERE id=?", (generate_password_hash(new_pw), session["user_id"]))
        conn.commit()
        return redirect("/")

    else:
        return render_template("change_password.html")



@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        lu = lookup(request.form.get("symbol"))
        if lu == None:
            return apology("invalid stock entry", 400)
        return render_template("quoted.html", stock_name=lu["name"], price=usd(lu["price"]), symbol=lu["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        users = db.execute("SELECT * FROM users").fetchall()
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must enter username", 400)

        for user in users:
            if user[1] == request.form.get("username"):
                return apology("username already exists", 400)

        if not password:
            return apology("password is required", 400)

        elif password != confirmation:
            return apology("passwords do not match", 400)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, generate_password_hash(password)))
        conn.commit()

        return redirect("/login")

    if request.method == "GET":
        return render_template("register.html")
        

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    owned_stocks = db.execute("SELECT stock FROM owned_stocks WHERE stock_id=?", (session["user_id"],)).fetchall()
    cash_before = db.execute("SELECT cash FROM users WHERE id=?", (session["user_id"],)).fetchall()
    stock_symbols = []
    for symbol in owned_stocks:
        stock_symbols.append(symbol[0])

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("please select stock")

        share = db.execute("SELECT shares FROM owned_stocks WHERE stock=?", (request.form.get("symbol"),)).fetchall()

        if not request.form.get("shares") or int(request.form.get("shares")) > int(share[0][0]):
            return apology("invalid shares")

        if int(share[0][0]) - int(request.form.get("shares")) == 0:
            db.execute("DELETE FROM owned_stocks WHERE stock=?", (request.form.get("symbol"),))
        else:
            db.execute("UPDATE owned_stocks SET shares=? WHERE stock=? AND stock_id=?",
                (int(share[0][0]) - int(request.form.get("shares")), request.form.get("symbol"), session["user_id"]))

        db.execute("UPDATE users SET cash=? WHERE id=?",
            (cash_before[0][0]+(int(request.form.get("shares"))*lookup(request.form.get("symbol"))["price"]), session["user_id"]))

        db.execute("INSERT INTO history(history_id, status, stock, shares, time) VALUES(?, ?, ?, ?, ?)",
            (session["user_id"], "Sell", request.form.get("symbol"), int(request.form.get("shares")), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        return redirect("/")
    else:
        return render_template("sell.html", stock_symbols=stock_symbols)
        

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
    conn.close()