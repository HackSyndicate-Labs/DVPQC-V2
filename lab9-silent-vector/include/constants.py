"""
Silent Vector Notarization Service — Configuration
====================================================
System-wide constants for the quantum-safe notarization platform.
"""

import os

# ── Dilithium-3 Parameters ──────────────────────────────────────
DILITHIUM_VARIANT = "Dilithium3"
DILITHIUM_Q = 8380417
DILITHIUM_N = 256
DILITHIUM_K = 6
DILITHIUM_L = 5
DILITHIUM_ETA = 4
DILITHIUM_GAMMA1 = (1 << 19)
DILITHIUM_GAMMA2 = (DILITHIUM_Q - 1) // 32

# ── Service Configuration ───────────────────────────────────────
SERVICE_NAME = "SilentNotary v3.1.2"
SERVICE_VERSION = "3.1.2"
MAX_DOCUMENT_SIZE = 1024 * 1024  # 1 MB
SIGNATURE_BATCH_SIZE = 16

# ── Telemetry Configuration ─────────────────────────────────────
TELEMETRY_ENABLED = True
TELEMETRY_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "telemetry")
TELEMETRY_ROTATION_INTERVAL = 3600  # seconds
TELEMETRY_METRICS_DEPTH = 48
TELEMETRY_SAMPLE_RATE = 1.0

# ── Key Storage ─────────────────────────────────────────────────
KEY_STORE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "keys")
KEY_FORMAT_VERSION = 2

# ── Protocol ────────────────────────────────────────────────────
HASH_ALGORITHM = "sha3-256"
NOTARIZATION_PREFIX = b"SILENT_NOTARY_V3::"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
