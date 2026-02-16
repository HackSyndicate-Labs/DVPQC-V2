"""
Crystal Echo - System Constants
===============================

Configuration constants for the Crystal Lattice Key Exchange System.
"""

# Kyber Parameters
KYBER_VARIANT = "Kyber768"  # Security Level 3 (192-bit)

# Kyber768 sizes (from NIST specification)
KYBER768_PUBLIC_KEY_BYTES = 1184
KYBER768_SECRET_KEY_BYTES = 2400
KYBER768_CIPHERTEXT_BYTES = 1088
KYBER768_SHARED_SECRET_BYTES = 32

# System Configuration
MAX_KEY_STORE_SIZE = 1000
KEY_ROTATION_INTERVAL = 3600  # seconds
SESSION_TIMEOUT = 300  # seconds

# Protocol Constants
PROTOCOL_VERSION = "2.1.0"
MAGIC_HEADER = b"CLSS"  # Crystal Lattice Security Systems
MESSAGE_TYPE_KEYGEN = 0x01
MESSAGE_TYPE_ENCAPS = 0x02
MESSAGE_TYPE_DECAPS = 0x03
MESSAGE_TYPE_ERROR = 0xFF

# Error Codes (some of these leak information in the vulnerable implementation)
ERROR_SUCCESS = 0x00
ERROR_INVALID_CIPHERTEXT = 0x01
ERROR_DECRYPTION_FAILED = 0x02
ERROR_REENCRYPTION_MISMATCH = 0x03
ERROR_KEY_NOT_FOUND = 0x04
ERROR_SESSION_EXPIRED = 0x05
ERROR_INTERNAL = 0xFF

# Vulnerable Configuration Flags
# These should all be True in a secure implementation
ENABLE_FULL_REENCRYPTION = False  # VULNERABLE: Skips re-encryption in some cases
ENABLE_CONSTANT_TIME_COMPARE = False  # VULNERABLE: Variable time comparison
ENABLE_IMPLICIT_REJECTION = False  # VULNERABLE: Error messages leak info
ENABLE_CIPHERTEXT_VALIDATION = False  # VULNERABLE: Incomplete validation

# Debug/Logging (should be False in production)
DEBUG_MODE = True
VERBOSE_ERRORS = True  # VULNERABLE: Detailed error messages
LOG_TIMING = True  # VULNERABLE: Timing information logged
