"""
Encrypts AI provider API keys at rest. The Fernet key is generated once
on first run and stored outside the database (a stolen/leaked DB file
alone is then useless without also having this file). Never log or
return this key or the encryption key itself via any API response.
"""

import os
from cryptography.fernet import Fernet

SECRET_PATH = os.environ.get(
    "CERBERUS_SECRET_PATH",
    os.path.join(os.path.dirname(__file__), ".instance_secret"),
)


def _load_or_create_key() -> bytes:
    try:
        fd = os.open(SECRET_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            key = Fernet.generate_key()
            os.write(fd, key)
            return key
        finally:
            os.close(fd)
    except FileExistsError:
        with open(SECRET_PATH, "rb") as f:
            return f.read().strip()


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
