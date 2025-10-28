import secrets
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

'''
base64.b64encode() = "zabal binárne dáta"

.decode('utf-8') = "premeň na text pre DB"

.encode('utf-8') = "premeň text späť na bajty"

base64.b64decode() = "rozbal bajty na pôvodné dáta"
'''

class PasswordManager:
    def __init__(self):
        self.salt_size = 16
        self.key_lenght = 32
        self.n = 2**14
        self.r = 8
        self.p = 1

    def hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(self.salt_size)

        kdf = Scrypt(
            salt = salt,
            length = self.key_lenght,
            n = self.n,
            r = self.r,
            p = self.p
        )

        password_bytes = password.encode('utf-8')
        key = kdf.derive(password_bytes)
        combined = key + salt

        return base64.b64encode(combined).decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        try:
            combined = base64.b64decode(hashed_password.encode('utf-8'))

            salt = combined[:self.salt_size]
            stored_key = combined[self.salt_size:]

            kdf = Scrypt(
                salt = salt,
                length = self.key_lenght,
                n=self.n,
                r=self.n,
                p=self.p
            )

            password_bytes = password.encode('utf-8')
            kdf.verify(password_bytes,stored_key)
            return True

        except (InvalidKey, ValueError):
            return False

