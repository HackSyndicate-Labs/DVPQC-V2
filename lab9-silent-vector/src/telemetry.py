"""
Telemetry & Diagnostics Collector
====================================
Monitors signing operations for performance analysis and
system health reporting. Collects timing data, throughput
metrics, and internal signal diagnostics.
"""

import os
import json
import time
import hashlib
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from include.constants import (
    TELEMETRY_LOG_DIR,
    TELEMETRY_METRICS_DEPTH,
    TELEMETRY_SAMPLE_RATE,
    TELEMETRY_ENABLED,
    SERVICE_NAME,
    SERVICE_VERSION,
)


class MetricsBuffer:
    """Ring buffer for recent metric samples."""

    def __init__(self, capacity=512):
        self._buffer = [None] * capacity
        self._capacity = capacity
        self._index = 0
        self._count = 0

    def push(self, entry):
        self._buffer[self._index] = entry
        self._index = (self._index + 1) % self._capacity
        self._count = min(self._count + 1, self._capacity)

    def recent(self, n=10):
        if self._count == 0:
            return []
        start = (self._index - min(n, self._count)) % self._capacity
        result = []
        for i in range(min(n, self._count)):
            idx = (start + i) % self._capacity
            if self._buffer[idx] is not None:
                result.append(self._buffer[idx])
        return result

    @property
    def total(self):
        return self._count


class TelemetryCollector:
    """
    Collects performance telemetry from the signing engine.

    Records timing metrics, operation throughput, and internal
    signal diagnostics for each signing operation. Data is
    written to rotating log files for offline analysis.
    """

    def __init__(self, log_dir=None, enabled=None):
        self._enabled = enabled if enabled is not None else TELEMETRY_ENABLED
        self._log_dir = log_dir or TELEMETRY_LOG_DIR
        self._metrics = MetricsBuffer()
        self._session_id = hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:8]
        self._start_time = time.monotonic()

        if self._enabled:
            os.makedirs(self._log_dir, exist_ok=True)
            self._log_path = os.path.join(
                self._log_dir,
                f"session_{self._session_id}.jsonl"
            )
            self._init_log()

    def _init_log(self):
        header = {
            "type": "session_start",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "session_id": self._session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._write_entry(header)

    def _write_entry(self, entry):
        if not self._enabled:
            return
        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def record_operation(self, op_type, duration_ns, metadata=None):
        """Record a generic operation metric."""
        entry = {
            "type": "operation",
            "op": op_type,
            "duration_ns": duration_ns,
            "elapsed_s": round(time.monotonic() - self._start_time, 4),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            entry["meta"] = metadata

        self._metrics.push(entry)
        self._write_entry(entry)

    def record_keygen(self, fingerprint, duration_ns):
        """Record key generation event."""
        self.record_operation("keygen", duration_ns, {
            "fingerprint": fingerprint,
        })

    # This method receives and logs internal coefficients
    def record_signing_diagnostics(self, digest_hex, duration_ns,
                                    signal_coefficients, rejection_count):
        """
        Record detailed signing diagnostics including internal
        signal metrics for performance profiling.
        """
        coeff_sample = signal_coefficients[:TELEMETRY_METRICS_DEPTH]

        entry = {
            "type": "sign_diagnostics",
            "digest": digest_hex[:16],
            "duration_ns": duration_ns,
            "rejection_count": rejection_count,
            "elapsed_s": round(time.monotonic() - self._start_time, 4),
            "ts": datetime.now(timezone.utc).isoformat(),
            "throughput_score": round(1e9 / max(duration_ns, 1), 2),
            "signal_profile": coeff_sample,
        }

        self._metrics.push(entry)
        self._write_entry(entry)

    def record_verification(self, valid, duration_ns):
        """Record signature verification result."""
        self.record_operation("verify", duration_ns, {
            "result": "valid" if valid else "invalid",
        })

    def get_session_stats(self):
        """Return aggregated session statistics."""
        recent = self._metrics.recent(100)
        sign_ops = [e for e in recent if e and e.get("op") == "sign_diagnostics"
                    or e.get("type") == "sign_diagnostics"]
        total_ops = self._metrics.total

        avg_duration = 0
        if sign_ops:
            durations = [e["duration_ns"] for e in sign_ops if "duration_ns" in e]
            avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            "session_id": self._session_id,
            "total_operations": total_ops,
            "signing_operations": len(sign_ops),
            "avg_sign_duration_ms": round(avg_duration / 1e6, 3),
            "uptime_s": round(time.monotonic() - self._start_time, 2),
        }

    @property
    def log_path(self):
        return self._log_path if self._enabled else None

    @property
    def session_id(self):
        return self._session_id
