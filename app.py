# Hopes: add passwords, search passwords, change passwords, delete passwords, generate passwords, add notes
# Add page: insert website url, website name, password confirmation, password generation*
# Account management page: change user password, delete account
# Home page: shows current website passwords, comments, and a search feature

import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, valid

from datetime import datetime
import random
import string

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Python 3 to use SQLite database
con = sqlite3.connect("password.db", check_same_thread=False)
db = con.cursor()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Displays users portfolio"""
    
    # If the user uses the search feature
    if request.method == "POST":
        # Get users search
        query = request.form.get("q")
        
        # Obtail the users accounts that contain the search
        portfolio = db.execute(
            "SELECT * FROM portfolio WHERE user_id = ? AND (name LIKE ? OR notes LIKE ?) ORDER BY date DESC",
            (session["user_id"], '%'+query+'%', '%'+query+'%',)
        )
        con.commit()
        
        # Check if portfolio contains data
        portfolio = portfolio.fetchall()

        # If the users portfolio contains data, pass it to index.html
        if len(portfolio) > 0:
            return render_template("index.html", portfolio=portfolio)
        
        # Otherwise return an empty list
        else:
            return render_template("index.html", portfolio=[])

    else:
        # Obtail users portfolio
        portfolio = db.execute(
            "SELECT * FROM portfolio WHERE user_id = ? ORDER BY date DESC",
            (session["user_id"],)
        )
        con.commit()
        
        # Check if portfolio contains data
        portfolio = portfolio.fetchall()

        # If the users portfolio contains data, pass it to index.html
        if len(portfolio) > 0:
            return render_template("index.html", portfolio=portfolio)
        
        # Otherwise return an empty list
        else:
            return render_template("index.html", portfolio=[])


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Update or delete user account"""

    if request.method == "POST":
        # If the user clicks save changes
        if 'update' in request.form:

            # Obtain input
            new_username = request.form.get("newusername")
            new_password = request.form.get("newpassword")
            confirmation = request.form.get("confirmpassword")
            old_password = request.form.get("oldpassword")
            
            # Obtain user info
            db.execute(
                "SELECT * FROM users WHERE id = ?",
                (session["user_id"],)
            )
            con.commit()
            row = db.fetchone()

            # Variable to confirm if the user wants to keep the same username
            same_username = False

            # Obtain users current username
            old_username = row[1]

            # If the user wants the same username, set bool to true
            if old_username == new_username:
                same_username = True

            # Confirm passwords match
            if new_password != confirmation:
                flash("New Passwords Must Match")        
                return redirect("/account")
            
            # Ensure password contains a uppercase, lowercase and number
            if not valid(new_password):
                flash("Password must contain an uppercase, lowercase and number")
                return redirect("/account")

            # If password is incorrect, flash the user
            elif not check_password_hash(row[2], old_password):
                flash("Incorrect Password")        
                return redirect("/account")

            # Obtain usernames
            usernames = db.execute(
                "SELECT username FROM users WHERE username = ?", 
                (new_username,)
            )

            # If the desired username is already in use 
            # and the user changes their username, cancel the update
            if len(usernames.fetchall()) != 0 and same_username == False:
                flash("Username is already taken")
                return redirect("/account")
            
            # Generate password hash
            hash = generate_password_hash(new_password)

            # Update the users table
            db.execute(
                "UPDATE users SET username = ?, hash = ? WHERE id = ?",
                (str(new_username), str(hash), session["user_id"])
            )
            con.commit()

            # Redirect the user
            flash("Successfully Updated Account Details")        
            return redirect("/account")
        
        # If the user clicks delete
        elif 'delete' in request.form:

            # Delete from users
            db.execute(
                "DELETE FROM users WHERE id = ?",
                (session["user_id"],)
            )

            # Log the user out  
            return redirect("/logout")
    
    else:
         # Obtail users portfolio
        values = db.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        )
        con.commit()
        # Obtain a list of tuples
        values = values.fetchone()
        
        # Convert to a dict for convenience
        keys = ["id", "username"]
        user = dict(zip(keys, values))

        # Obtain all of the users portfolio
        accounts = db.execute(
            "SELECT * FROM portfolio WHERE user_id = ?",
            (session["user_id"],)
        )
        con.commit()
        accounts = accounts.fetchall()

        # Get the number of passwords saved
        passwords = len(accounts)

        # Obtain the date of the users last entry or edit
        date = db.execute(
            "SELECT date FROM portfolio WHERE user_id = ? ORDER BY date DESC LIMIT 1",
            (session["user_id"],)
        )
        con.commit()
        date = date.fetchone()

        # If none has been saved, return N/A
        if date == None:
            date = "N/A"
        # Else return the date element
        else:
            date = date[0]

        return render_template("account.html", user=user, passwords=passwords, date=date)



@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Adds new login details"""

    # If a login was entered
    if request.method == "POST":
        # Obtain user input
        name = request.form.get("name")
        url = request.form.get("url")
        login = request.form.get("login")
        password = request.form.get("password")
        notes = request.form.get("notes")

        # Convert datetime
        date = datetime.now()
        date = date.strftime("%x")

        # Obtain id
        rows = db.execute("SELECT * FROM users WHERE id = ?", 
                          (session["user_id"],)
                          )
        con.commit()
        id = rows.fetchall()[0][0]

        # Store users login details
        db.execute(
            "INSERT INTO portfolio (user_id, name, url, login, password, notes, date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(id), str(name), str(url), str(login), str(password), str(notes), date,)
        )
        con.commit()

        # Return user to homepage
        flash("Successfully Saved Your %s Login Details!" % name)
        return redirect("/")

    # Return the add page
    else:
        return render_template("add.html")


@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    """Displays edit form"""

    if request.method == "POST":
         # Obtail users portfolio
        values = db.execute(
            "SELECT * FROM portfolio WHERE id = ?",
            (request.form.get("id"),)
        )
        con.commit()
        # Obtain a list of tuples
        values = values.fetchone()
        
        # Convert to a dict for convenience
        keys = ["id", "user_id", "name", "url", "login", "password", "notes", "date"]
        portfolio = dict(zip(keys, values))

        return render_template("edit.html", portfolio=portfolio)
    
    else:
        return redirect("/")


@app.route("/edited", methods=["POST"])
@login_required
def edited():
    """Edits users login details"""

    # If the user clicks save changes
    if 'edit' in request.form:
        # Obtain user input
        id = request.form.get("id")
        name = request.form.get("name")
        url = request.form.get("url")
        login = request.form.get("login")
        password = request.form.get("password")
        notes = request.form.get("notes")

        # Convert datetime
        date = datetime.now()
        date = date.strftime("%x")
        
        # Update users login details
        db.execute(
            "UPDATE portfolio SET name = ?, url = ?, login = ?, password = ?, notes = ?, date = ? WHERE id = ?",
            (str(name), str(url), str(login), str(password), str(notes), date, int(id),)
        )
        con.commit()

        # Return user to homepage
        flash("Successfully Updated Your %s Login Details!" % name)        
        return redirect("/")
    
    # If the user clicks delete
    elif 'delete' in request.form:
        # Obtain login id and name
        id = request.form.get("id")
        name = request.form.get("name")

        # Delete the users login details from db
        db.execute(
            "Delete FROM portfolio WHERE id = ?",
            (id,)
        )
        con.commit()

        # Redirect to homepage with message
        flash("Deleted Your %s Login Details!" % name)        
        return redirect("/")


@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate():
    """Generates a password"""

    # If user generates a password
    if request.method == "POST":

        # Ensure password length is less than max
        max = 20
        n = request.form.get("length")

        if int(n) > max:
            flash("Password length must be 20 or lower") 
            return redirect("/generate")

        # Generate and randomize printable characters
        letters = string.printable
        
        # Remove whitespace
        letters = letters.strip()
        
        password = ''.join(random.choice(letters) for i in range(int(n)))

        # Return the password to user
        return render_template("generate.html", password=password, n=n)

    else:
        return render_template("generate.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username")
            return redirect("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password")
            return redirect("/login")

        # Query database for username
        db.execute(
            "SELECT * FROM users WHERE username = ?", 
            (request.form.get("username"),)
        )

        rows = db.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0][2], request.form.get("password")
        ):
            flash("invalid username and/or password")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        flash("Welcome Back %s!" % request.form.get("username"))

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registers new user"""

    # If the user submitted input
    if request.method == "POST":
        # Store user input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was created
        if not username:
            flash("must provide username")
            return redirect("/register")

        # Ensure username isn't taken
        usernames = db.execute(
            "SELECT username FROM users WHERE username = ?", 
            (username,)
        )
        con.commit()

        if len(usernames.fetchall()) != 0:
            flash("username already exists")
            return redirect("/register")

        # Ensure password was created
        elif not password:
            flash("must provide password")
            return redirect("/register")

        # Ensure passwords match
        elif password != confirmation:
            flash("passwords don't match")
            return redirect("/register")

        # Ensure password contains a uppercase, lowercase and number
        if not valid(password):
            flash("Password must contain an uppercase, lowercase and number")
            return redirect("/register")

        # Generate password hash
        hash = generate_password_hash(password)

        # If user account is free of errors, store data in db
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash))
        con.commit()

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", 
            (username,)
        )

        # Remember which user has logged in
        session["user_id"] = rows.fetchone()[0]

        # Redirect user to home page
        return redirect("/")

    # Otherwise, if its a GET, present the register page
    else:
        return render_template("register.html")
