from flask import redirect, session
from functools import wraps
from re import search


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def valid(password):
    """Validates users password"""

    # Ensure created password has atleast an uppercase, lowercase and number
    if not search("[A-Z]", password):
        return False
    elif not search("[a-z]", password):
        return False
    elif not search("[0-9]", password):
        return False
    return True