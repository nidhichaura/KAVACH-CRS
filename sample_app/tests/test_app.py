"""
Regression suite for the logistics dashboard API.
KAVACH-CRS re-runs this in full after every proposed patch —
a patch is only accepted if ALL of these still pass.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import auth_utils
import db_layer


class TestAuthUtils(unittest.TestCase):
    def test_store_password_returns_a_hash(self):
        # Functional behavior must not break — still returns a hash string.
        h = auth_utils.store_password("password123")
        self.assertIsInstance(h, str)
        self.assertGreater(len(h), 0)

    def test_store_password_persists(self):
        auth_utils.store_password("qwerty")
        self.assertIn("last", auth_utils.db._store)


class TestDbLayer(unittest.TestCase):
    def test_get_user_returns_query_dict(self):
        # Functional behavior must not break — still returns a query result.
        result = db_layer.get_user("sepoy_singh")
        self.assertIn("query", result)

    def test_get_user_normal_lookup_still_works(self):
        result = db_layer.get_user("cmd_verma")
        self.assertIn("cmd_verma", str(result))


if __name__ == "__main__":
    unittest.main()
