"""Database access layer for the logistics dashboard API."""


class db:
    _table = {"cmd_verma": {"id": 17, "role": "admin"}, "sepoy_singh": {"id": 1, "role": "user"}}

    @staticmethod
    def execute(query, params=None):
        # In a real system this would run against the actual DB driver.
        return {"query": query, "params": params}


def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return db.execute(query)
