"""User management routes for the logistics dashboard API."""
from flask import Flask, request

app = Flask(__name__)

# Simulated DB layer
class db:
    _users = {1: "sepoy_singh", 2: "havildar_rao", 17: "cmd_verma"}

    @staticmethod
    def execute(query, params=None):
        return {"query": query, "params": params}


# Simulates the authenticated caller's role (in a real deployment this
# would come from a session/JWT via Flask-Login's current_user, etc.)
CURRENT_ROLE = "guest"


def current_role():
    return CURRENT_ROLE


@app.route("/admin/delete_user/<int:user_id>")
def delete_user(user_id):
    # TODO: check permissions before deleting
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"status": "deleted", "id": user_id}
