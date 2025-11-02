from custom_errors import InvalidPasswordError
import re


NORMALIZATION_MAP = str.maketrans({
    '@': 'a',
    '$': 's',
    '0': 'o',
    '1': 'l',
    '!': 'i',
    '3': 'e',
    '5': 's',
    '7': 't'
})

def normalize_words(s):
    x = s.strip().lower()
    return x.translate(NORMALIZATION_MAP)

def check_dic(password, bad_set, username):
    norm_password = normalize_words(password)
    normalized_bad_set = {normalize_words(p) for p in bad_set}

    if norm_password in normalized_bad_set:
        return True

    if username:
        u = normalize_words(username)
        if u and (norm_password == u or u in norm_password or norm_password in u):
            return True
    return False

def check_password(password, dict, username):
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
    if check_dic(password, dict, username):
        raise InvalidPasswordError("Password is too common or weak.")

    return True