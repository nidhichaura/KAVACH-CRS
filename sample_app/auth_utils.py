"""Authentication utilities for the logistics dashboard API."""
import hashlib


class db:
    _store = {}

    @staticmethod
    def save(hashed):
        db._store["last"] = hashed
        return True


def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.save(hashed)
    return hashed
