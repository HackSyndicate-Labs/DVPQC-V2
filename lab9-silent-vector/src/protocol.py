"""
Document Notarization Protocol
=================================
High-level protocol for quantum-safe document notarization.
Manages the complete lifecycle: key provisioning, document
signing, certificate generation, and verification.
"""

import os
import sys
import time
import json
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from include.constants import (
    SERVICE_NAME,
    SERVICE_VERSION,
    MAX_DOCUMENT_SIZE,
    TIMESTAMP_FORMAT,
    SIGNATURE_BATCH_SIZE,
)
from src.dilithium_signer import DilithiumSigner
from src.signature_engine import SignatureEngine
from src.key_manager import KeyManager
from src.telemetry import TelemetryCollector


class NotarizationCertificate:
    """Represents a notarized document certificate."""

    def __init__(self, document_hash, signature, public_key_fingerprint,
                 timestamp, metadata):
        self.document_hash = document_hash
        self.signature = signature
        self.public_key_fingerprint = public_key_fingerprint
        self.timestamp = timestamp
        self.metadata = metadata

    def to_dict(self):
        return {
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "document_hash": self.document_hash,
            "signature_hex": self.signature.hex(),
            "signer_fingerprint": self.public_key_fingerprint,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return (
            f"NotarizationCertificate("
            f"doc={self.document_hash[:12]}..., "
            f"signer={self.public_key_fingerprint})"
        )


class NotarizationService:
    """
    Quantum-safe document notarization service.

    Provides a complete signing pipeline with Dilithium-3,
    including key management and performance telemetry.

    Usage:
        svc = NotarizationService()
        cert = svc.notarize(b"my document content")
        valid = svc.verify(b"my document content", cert)
    """

    def __init__(self, data_dir=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._data_dir = data_dir or os.path.join(base_dir, "data")

        self._signer = DilithiumSigner()
        self._key_manager = KeyManager(
            store_dir=os.path.join(self._data_dir, "keys")
        )
        self._telemetry = TelemetryCollector(
            log_dir=os.path.join(self._data_dir, "telemetry")
        )
        self._engine = SignatureEngine(self._signer, self._telemetry)

        self._initialized = False
        self._certificates = []

    def initialize(self):
        """Initialize the service: load or generate keys."""
        existing = self._key_manager.get_active_key()
        if existing:
            self._signer.load_keypair(existing.public_key, existing.secret_key)
            fingerprint = existing.fingerprint
        else:
            t0 = time.perf_counter_ns()
            pub, sec = self._signer.generate_keypair()
            t1 = time.perf_counter_ns()
            record = self._key_manager.store_key(pub, sec)
            fingerprint = record.fingerprint
            self._telemetry.record_keygen(fingerprint, t1 - t0)

        self._initialized = True
        return fingerprint

    def _ensure_initialized(self):
        if not self._initialized:
            self.initialize()

    def notarize(self, document, context=None):
        """
        Notarize a document.

        Args:
            document: Raw document bytes to notarize.
            context: Optional context string for domain separation.

        Returns:
            NotarizationCertificate with the signature and metadata.
        """
        self._ensure_initialized()

        if len(document) > MAX_DOCUMENT_SIZE:
            raise ValueError(
                f"Document exceeds maximum size ({len(document)} > {MAX_DOCUMENT_SIZE})"
            )

        signature, digest_hex, metadata = self._engine.sign_document(
            document, context
        )

        timestamp = datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)
        fingerprint = self._signer.fingerprint()

        cert = NotarizationCertificate(
            document_hash=digest_hex,
            signature=signature,
            public_key_fingerprint=fingerprint,
            timestamp=timestamp,
            metadata=metadata,
        )

        self._certificates.append(cert)
        return cert

    def notarize_batch(self, documents, context=None):
        """Notarize multiple documents in sequence."""
        self._ensure_initialized()
        results = []
        for i, doc in enumerate(documents):
            cert = self.notarize(doc, context)
            results.append(cert)
        return results

    def verify(self, document, certificate, context=None):
        """
        Verify a notarized document against its certificate.

        Args:
            document: Original document bytes.
            certificate: NotarizationCertificate or dict.

        Returns:
            bool: True if signature is valid.
        """
        self._ensure_initialized()

        if isinstance(certificate, dict):
            sig = bytes.fromhex(certificate["signature_hex"])
        else:
            sig = certificate.signature

        return self._engine.verify_document(
            document, sig, context=context
        )

    def get_public_key(self):
        """Return the service's current public key."""
        self._ensure_initialized()
        return self._signer.public_key

    def get_service_info(self):
        """Return service status and statistics."""
        self._ensure_initialized()
        return {
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "algorithm_info": self._signer.get_algorithm_info(),
            "engine_stats": self._engine.get_engine_stats(),
            "keys_stored": len(self._key_manager.list_keys()),
            "certificates_issued": len(self._certificates),
            "telemetry_session": self._telemetry.session_id,
            "telemetry_log": self._telemetry.log_path,
        }

    @property
    def telemetry_log_path(self):
        """Path to the current telemetry session log."""
        return self._telemetry.log_path

    @property
    def engine(self):
        return self._engine

    @property
    def key_manager(self):
        return self._key_manager
