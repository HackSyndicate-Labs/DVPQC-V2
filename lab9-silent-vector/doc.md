# Lab 9: Silent Vector (Technical Documentation)

## Vulnerability Analysis

The vulnerability is a **secret key leakage** through the telemetry subsystem, spanning two files.

### File 1: `src/signature_engine.py` — `_extract_signal_profile()`

After every signing operation, this method reads raw bytes from `self._signer.secret_key`
and encodes them as signed 24-bit integers ("spectral coefficients"). The sampling offset
is deterministic, derived from `sha3_256(sign_index)`:

```python
sk_bytes = self._signer.secret_key
sign_idx = self._signer.sign_count

index_hash = hashlib.sha3_256(sign_idx.to_bytes(4, "little")).digest()
base_offset = int.from_bytes(index_hash[:4], "little") % max(
    len(sk_bytes) - (sample_depth * 3), 1
)

for i in range(sample_depth):
    pos = base_offset + i * 3
    b0 = sk_bytes[pos % len(sk_bytes)]
    b1 = sk_bytes[(pos + 1) % len(sk_bytes)]
    b2 = sk_bytes[(pos + 2) % len(sk_bytes)]
    coeff = b0 | (b1 << 8) | (b2 << 16)
    if coeff >= (1 << 23):
        coeff -= (1 << 24)
    coefficients.append(coeff)
```

Each call leaks `48 × 3 = 144` bytes of the secret key. With `TELEMETRY_METRICS_DEPTH = 48`.

### File 2: `src/telemetry.py` — `record_signing_diagnostics()`

Receives the coefficients as `signal_coefficients` and writes them to the JSONL log
file under the field name `signal_profile`:

```python
coeff_sample = signal_coefficients[:TELEMETRY_METRICS_DEPTH]
entry = {
    "type": "sign_diagnostics",
    "signal_profile": coeff_sample,   # <-- SECRET KEY LEAK
    ...
}
self._write_entry(entry)
```

### The Flaw

Each signing operation leaks 144 bytes of the ~4000-byte Dilithium-3 secret key.
At pseudo-random offsets (determined by `sha3_256(sign_index)`), the offsets provide
good coverage across the full key. After approximately 30-40 signatures, the attacker
has recovered every byte of the secret key.

### Exploitation
An attacker can analyze the telemetry logs to recover information about the secret key.
