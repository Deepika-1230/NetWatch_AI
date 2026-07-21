from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any


class AuthManager:
    """Small password manager for the local NetWatch AI login gate."""

    DEFAULT_PASSWORD = "admin123"
    ITERATIONS = 160_000

    def __init__(self, app_root: Path) -> None:
        self.auth_path = app_root / "database" / "auth.json"
        self.auth_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.auth_path.exists():
            self._save_record(self._new_record(self.DEFAULT_PASSWORD, first_run=True))

    def verify_password(self, password: str) -> bool:
        record = self._load_record()
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["password_hash"])
        actual = self._hash_password(password, salt, int(record.get("iterations", self.ITERATIONS)))
        return hmac.compare_digest(actual, expected)

    def change_password(self, current_password: str, new_password: str) -> tuple[bool, str]:
        if not self.verify_password(current_password):
            return False, "Current password is incorrect."
        if len(new_password.strip()) < 6:
            return False, "New password must be at least 6 characters."
        self.set_password(new_password.strip())
        return True, "Login password changed."

    def set_password(self, new_password: str) -> tuple[bool, str]:
        if len(new_password.strip()) < 6:
            return False, "Password must be at least 6 characters."
        self._save_record(self._new_record(new_password.strip(), first_run=False))
        return True, "Login password updated."

    def reset_to_default(self) -> None:
        self._save_record(self._new_record(self.DEFAULT_PASSWORD, first_run=True))

    def is_default_password(self) -> bool:
        record = self._load_record()
        return bool(record.get("first_run", False))

    def _load_record(self) -> dict[str, Any]:
        try:
            return json.loads(self.auth_path.read_text(encoding="utf-8"))
        except Exception:
            record = self._new_record(self.DEFAULT_PASSWORD, first_run=True)
            self._save_record(record)
            return record

    def _save_record(self, record: dict[str, Any]) -> None:
        self.auth_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    def _new_record(self, password: str, first_run: bool) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        digest = self._hash_password(password, salt, self.ITERATIONS)
        return {
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": base64.b64encode(digest).decode("ascii"),
            "iterations": self.ITERATIONS,
            "first_run": first_run,
            "updated_at": time.time(),
        }

    @staticmethod
    def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
