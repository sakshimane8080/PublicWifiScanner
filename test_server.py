import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

import app as application


class BackendIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_file = os.path.join(self.temp_dir.name, "test.sqlite3")
        self.legacy_file = os.path.join(self.temp_dir.name, "users.json")
        self.database_patch = patch.object(
            application,
            "database_url",
            return_value="sqlite:///{}".format(self.database_file.replace("\\", "/")),
        )
        self.legacy_patch = patch.object(application, "LEGACY_USERS_FILE", self.legacy_file)
        self.database_patch.start()
        self.legacy_patch.start()
        self.addCleanup(self.database_patch.stop)
        self.addCleanup(self.legacy_patch.stop)
        application.initialize_database()

        self.previous_secure_cookie = application.app.config["SECURE_COOKIES"]
        application.app.config["SECURE_COOKIES"] = False
        self.addCleanup(self.restore_secure_cookie_setting)
        self.client = application.app.test_client()
        self.origin = {"Origin": "http://localhost"}

    def restore_secure_cookie_setting(self):
        application.app.config["SECURE_COOKIES"] = self.previous_secure_cookie
        self.temp_dir.cleanup()

    def post(self, path, body, headers=None):
        return self.client.post(
            path,
            json=body,
            headers={**self.origin, **(headers or {})},
        )

    def register(self, email="test@example.com", password="safe-password-42"):
        return self.post(
            "/api/register",
            {
                "name": "Test User",
                "email": email,
                "password": password,
            },
        )

    def login(self, email="test@example.com", password="safe-password-42"):
        return self.post("/api/login", {"email": email, "password": password})

    def test_registration_login_protected_api_and_logout(self):
        response = self.register()
        self.assertEqual(response.status_code, 201)

        with closing(sqlite3.connect(self.database_file)) as connection:
            password_hash = connection.execute(
                "SELECT password_hash FROM users WHERE email = ?",
                ("test@example.com",),
            ).fetchone()[0]
        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        self.assertNotEqual(password_hash, "safe-password-42")

        response = self.post("/api/risk", {"wifiType": "open"})
        self.assertEqual(response.status_code, 401)

        response = self.login(password="wrong-password")
        self.assertEqual(response.status_code, 401)

        response = self.login()
        self.assertEqual(response.status_code, 200)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)

        response = self.client.get("/api/me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["name"], "Test User")

        response = self.post("/api/risk", {"wifiType": "open"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], 85)

        response = self.post("/api/report", {"wifiType": "strong"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertIn(b"Simulated Risk Score: 15%", response.data)

        response = self.post("/api/logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_registration_validation_duplicates_and_foreign_origins(self):
        response = self.register(password="short")
        self.assertEqual(response.status_code, 400)

        response = self.register()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.register().status_code, 409)

        response = self.post(
            "/api/register",
            {
                "name": "Other User",
                "email": "other@example.com",
                "password": "safe-password-42",
            },
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "safe-password-42"},
        )
        self.assertEqual(response.status_code, 403)

    def test_invalid_risk_type_and_page_authentication(self):
        self.register()
        self.login()

        response = self.post("/api/risk", {"wifiType": "invalid"})
        self.assertEqual(response.status_code, 400)

        self.client.post("/api/logout", json={}, headers=self.origin)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login.html")

    def test_migrates_legacy_plaintext_passwords_to_hashes(self):
        with open(self.legacy_file, "w", encoding="utf-8") as legacy_file:
            json.dump(
                {
                    "legacy@example.com": {
                        "name": "Legacy User",
                        "password": "legacy-secret",
                    }
                },
                legacy_file,
            )

        application.initialize_database()

        self.assertFalse(os.path.exists(self.legacy_file))
        with closing(sqlite3.connect(self.database_file)) as connection:
            password_hash = connection.execute(
                "SELECT password_hash FROM users WHERE email = ?",
                ("legacy@example.com",),
            ).fetchone()[0]
        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        self.assertTrue(application.verify_password("legacy-secret", password_hash))
        self.assertFalse(application.verify_password("not-the-password", password_hash))

    def test_secure_cookie_can_be_enabled_for_https_hosting(self):
        self.register()
        application.app.config["SECURE_COOKIES"] = True
        response = self.client.post(
            "/api/login",
            json={"email": "test@example.com", "password": "safe-password-42"},
            headers={"Origin": "https://localhost"},
            base_url="https://localhost",
        )
        self.assertIn("Secure", response.headers["Set-Cookie"])

    def test_https_is_required_when_secure_cookies_are_enabled(self):
        application.app.config["SECURE_COOKIES"] = True
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 308)
        self.assertEqual(response.headers["Location"], "https://localhost/health")


if __name__ == "__main__":
    unittest.main()
