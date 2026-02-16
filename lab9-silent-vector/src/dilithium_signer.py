"""
Dilithium Signature Wrapper
=============================
Thin wrapper around CRYSTALS-Dilithium-3 for the notarization platform.
Provides key generation, signing, and verification primitives.
"""

import hashlib
import os
import sys

from dilithium_py.dilithium import Dilithium3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from include.constants import DILITHIUM_VARIANT


class DilithiumSigner:
    """
    Low-level interface to CRYSTALS-Dilithium-3.

    Wraps Dilithium operations with additional bookkeeping
    for the notarization service.
    """

    # Fixed algorithm parameters for Dilithium3
    PK_BYTES = 1952
    SK_BYTES = 4000
    SIG_BYTES = 3293

    def __init__(self, variant=None):
        self._variant = variant or DILITHIUM_VARIANT
        self._public_key = None
        self._secret_key = None
        self._sign_count = 0

    @property
    def variant(self):
        return self._variant

    @property
    def public_key(self):
        return self._public_key

    @property
    def secret_key(self):
        return self._secret_key

    @property
    def public_key_size(self):
        return self.PK_BYTES

    @property
    def secret_key_size(self):
        return self.SK_BYTES

    @property
    def signature_size(self):
        return self.SIG_BYTES

    @property
    def sign_count(self):
        return self._sign_count

    def generate_keypair(self):
        """Generate a fresh Dilithium-3 key pair."""
        self._public_key, self._secret_key = Dilithium3.keygen()
        return bytes(self._public_key), bytes(self._secret_key)

    def load_keypair(self, public_key, secret_key):
        """Load an existing key pair into the signer."""
        self._public_key = bytes(public_key)
        self._secret_key = bytes(secret_key)

    def sign(self, message):
        """
        Sign a message using the loaded secret key.

        Returns the raw Dilithium signature bytes.
        """
        if self._secret_key is None:
            raise RuntimeError("No secret key loaded - call generate_keypair() first")

        signature = Dilithium3.sign(self._secret_key, message)
        self._sign_count += 1
        return bytes(signature)

    def verify(self, message, signature, public_key=None):
        """
        Verify a Dilithium signature.

        Uses the loaded public key unless an explicit one is provided.
        """
        pk = public_key or self._public_key
        if pk is None:
            raise RuntimeError("No public key available for verification")

        return Dilithium3.verify(pk, message, signature)

    def get_algorithm_info(self):
        """Return algorithm metadata."""
        return {
            "name": self._variant,
            "version": "dilithium-py v0.6",
            "pk_bytes": self.PK_BYTES,
            "sk_bytes": self.SK_BYTES,
            "sig_bytes": self.SIG_BYTES,
            "nist_level": 3,
        }

    def fingerprint(self, key_bytes=None):
        """SHA3-256 fingerprint of the public key."""
        data = key_bytes or self._public_key
        if data is None:
            return None
        return hashlib.sha3_256(data).hexdigest()[:16]

