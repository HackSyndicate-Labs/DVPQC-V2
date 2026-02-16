"""
Silent Vector Notarization Service
====================================
Quantum-safe document notarization powered by CRYSTALS-Dilithium.

Modules:
    dilithium_signer  — Low-level Dilithium wrapper (liboqs)
    signature_engine  — Core signing engine with diagnostics
    key_manager       — Key lifecycle management
    telemetry         — Performance and diagnostics monitoring
    protocol          — Document notarization protocol
"""

from src.dilithium_signer import DilithiumSigner
from src.signature_engine import SignatureEngine
from src.key_manager import KeyManager
from src.telemetry import TelemetryCollector
from src.protocol import NotarizationService

__all__ = [
    "DilithiumSigner",
    "SignatureEngine",
    "KeyManager",
    "TelemetryCollector",
    "NotarizationService",
]
