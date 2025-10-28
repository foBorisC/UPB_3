from custom_errors import InvalidPasswordError
import re
'''Utility methods for password validation.'''

def check_password(password):
    if len(password) < 12:
        raise InvalidPasswordError("Password must be at least 12 characters long.")
    if password.isdigit():
        raise InvalidPasswordError("Password cannot be entirely numeric.")
    if password.islower():
        raise InvalidPasswordError("Mix lowercase and uppercase letters.")
    if password.find(' ') != -1:
        raise InvalidPasswordError("Password cannot contain spaces.")
    if not re.search(r'[.!?]', password):
        raise InvalidPasswordError("Password must contain at least one special character (., !, ?).")

    return True
