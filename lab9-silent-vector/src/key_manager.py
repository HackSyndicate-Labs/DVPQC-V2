"""
Key Lifecycle Manager
======================
Handles generation, serialization, and secure storage of
Dilithium key pairs for the notarization service.
"""

import os
import json
import hashlib
import time
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from include.constants import (
    KEY_STORE_DIR,
    KEY_FORMAT_VERSION,
    DILITHIUM_VARIANT,
    TIMESTAMP_FORMAT,
)


class KeyRecord:
    """Metadata envelope for a stored key pair."""

    def __init__(self, key_id, public_key, secret_key, created_at=None):
        self.key_id = key_id
        self.public_key = public_key
        self.secret_key = secret_key
        self.created_at = created_at or datetime.now(timezone.utc)
        self.fingerprint = hashlib.sha3_256(public_key).hexdigest()[:16]

    def to_dict(self):
        return {
            "key_id": self.key_id,
            "format_version": KEY_FORMAT_VERSION,
            "algorithm": DILITHIUM_VARIANT,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at.strftime(TIMESTAMP_FORMAT),
            "public_key_hex": self.public_key.hex(),
            "secret_key_hex": self.secret_key.hex(),
        }

    @classmethod
    def from_dict(cls, data):
        record = cls(
            key_id=data["key_id"],
            public_key=bytes.fromhex(data["public_key_hex"]),
            secret_key=bytes.fromhex(data["secret_key_hex"]),
            created_at=datetime.strptime(data["created_at"], TIMESTAMP_FORMAT),
        )
        return record


class KeyManager:
    """
    Manages Dilithium key pairs on disk.

    Keys are stored as JSON in the configured key store directory.
    Each key pair gets a unique identifier based on a monotonic counter
    and the public key fingerprint.
    """

    def __init__(self, store_dir=None):
        self.store_dir = store_dir or KEY_STORE_DIR
        os.makedirs(self.store_dir, exist_ok=True)
        self._counter = self._load_counter()
        self._cache = {}

    def _load_counter(self):
        counter_path = os.path.join(self.store_dir, ".counter")
        if os.path.exists(counter_path):
            with open(counter_path, "r") as f:
                return int(f.read().strip())
        return 0

    def _save_counter(self):
        counter_path = os.path.join(self.store_dir, ".counter")
        with open(counter_path, "w") as f:
            f.write(str(self._counter))

    def _next_key_id(self):
        self._counter += 1
        self._save_counter()
        ts = int(time.time() * 1000) & 0xFFFFFFFF
        return f"dk3-{ts:08x}-{self._counter:04d}"

    def store_key(self, public_key, secret_key, key_id=None):
        """Persist a key pair and return its KeyRecord."""
        if key_id is None:
            key_id = self._next_key_id()

        record = KeyRecord(key_id, public_key, secret_key)
        path = os.path.join(self.store_dir, f"{key_id}.json")
        with open(path, "w") as f:
            json.dump(record.to_dict(), f, indent=2)

        self._cache[key_id] = record
        return record

    def load_key(self, key_id):
        """Load a key pair by its identifier."""
        if key_id in self._cache:
            return self._cache[key_id]

        path = os.path.join(self.store_dir, f"{key_id}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Key '{key_id}' not found in store")

        with open(path, "r") as f:
            data = json.load(f)

        record = KeyRecord.from_dict(data)
        self._cache[key_id] = record
        return record

    def list_keys(self):
        """List all stored key identifiers."""
        keys = []
        for fname in os.listdir(self.store_dir):
            if fname.endswith(".json"):
                keys.append(fname[:-5])
        return sorted(keys)

    def get_active_key(self):
        """Return the most recently generated key, or None."""
        keys = self.list_keys()
        if not keys:
            return None
        return self.load_key(keys[-1])

    def rotate_key(self, signer):
        """Generate a new key pair via the given signer and store it."""
        pub, sec = signer.generate_keypair()
        record = self.store_key(pub, sec)
        return record
