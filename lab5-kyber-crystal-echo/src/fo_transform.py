"""
FO Transform - Fujisaki-Okamoto Transformation (VULNERABLE)
============================================================

This module implements the Fujisaki-Okamoto transform used to convert
Kyber's IND-CPA secure PKE into an IND-CCA secure KEM.

"""
"""

import oqs
import hashlib
import hmac
import time
from typing import Tuple, Optional
from dataclasses import dataclass
from enum import IntEnum

import sys
sys.path.insert(0, '..')
from include.constants import (
    KYBER_VARIANT,
    KYBER768_CIPHERTEXT_BYTES,
    KYBER768_SHARED_SECRET_BYTES,
    ENABLE_FULL_REENCRYPTION,
    ENABLE_CONSTANT_TIME_COMPARE,
    ENABLE_IMPLICIT_REJECTION,
    ENABLE_CIPHERTEXT_VALIDATION,
    DEBUG_MODE,
    VERBOSE_ERRORS,
    LOG_TIMING,
)


class DecapsulationResult(IntEnum):
    """Result codes for decapsulation operation."""
    SUCCESS = 0
    INVALID_LENGTH = 1
    DECRYPTION_ERROR = 2
    REENCRYPTION_MISMATCH = 3
    VALIDATION_FAILED = 4


@dataclass
class FOState:
    """Internal state of the FO transform."""
    decrypted_message: Optional[bytes] = None
    reencrypted_ciphertext: Optional[bytes] = None
    comparison_result: Optional[bool] = None
    timing_info: Optional[float] = None
    error_code: DecapsulationResult = DecapsulationResult.SUCCESS


class FOTransform:
    """
    Fujisaki-Okamoto Transform for Kyber KEM.
    
    This class implements the FO transform that provides IND-CCA security.
    
    VULNERABLE IMPLEMENTATION - Contains multiple security flaws.
    """
    
    def __init__(self, variant: str = KYBER_VARIANT):
        """
        Initialize the FO Transform.
        
        Args:
            variant: Kyber variant to use
        """
        self.variant = variant
        self._kem = oqs.KeyEncapsulation(variant)
        self._implicit_rejection_key: bytes = hashlib.sha256(b"CLSS_IMPLICIT_REJECTION").digest()
        self._state = FOState()
        
        # Get lengths from liboqs
        self._ciphertext_len = self._kem.details['length_ciphertext']
        self._shared_secret_len = self._kem.details['length_shared_secret']
        
    def _validate_ciphertext_length(self, ciphertext: bytes) -> bool:
        """
        Validate that ciphertext has correct length.
        
        VULNERABILITY: This is the ONLY validation performed on ciphertext
        when ENABLE_CIPHERTEXT_VALIDATION is False.
        """
        return len(ciphertext) == self._ciphertext_len
    
    def _validate_ciphertext_structure(self, ciphertext: bytes) -> bool:
        """
        Validate ciphertext internal structure.
        
        VULNERABILITY: This validation is INCOMPLETE and can be bypassed.
        A proper implementation would check the NTT coefficients are in range.
        """
        if not ENABLE_CIPHERTEXT_VALIDATION:
            # Skip detailed validation - VULNERABLE
            return True
        
        # Incomplete validation - only checks first few bytes
        # This misses many malformed ciphertexts
        if len(ciphertext) < 32:
            return False
        
        # Check that first component "looks valid"
        # This is NOT a proper validation!
        first_bytes = ciphertext[:32]
        if all(b == 0 for b in first_bytes):
            return False
        if all(b == 0xFF for b in first_bytes):
            return False
            
        return True
    
    def _should_skip_reencryption(self, ciphertext: bytes) -> bool:
        """
        Determine if re-encryption can be "safely" skipped.
        
        VULNERABILITY: This function incorrectly allows skipping re-encryption
        for certain ciphertext patterns, breaking IND-CCA security.
        
        The flawed logic assumes certain ciphertexts are "obviously valid"
        and don't need verification, but this is WRONG.
        """
        if ENABLE_FULL_REENCRYPTION:
            return False  # Secure behavior
        
        # VULNERABLE LOGIC: Skip re-encryption for "normal looking" ciphertexts
        # This is a performance "optimization" that breaks security
        
        # Check if ciphertext appears to be "well-formed"
        # Flawed heuristic: if entropy looks high, assume it's valid
        byte_set = set(ciphertext)
        entropy_estimate = len(byte_set) / 256.0
        
        # If "entropy" is high, skip re-encryption
        # Heuristic optimization: if entropy is high enough, we assume validity
        # to save the expensive re-encryption step.
        if entropy_estimate > 0.7:
            if DEBUG_MODE:
                print(f"[DEBUG] Skipping re-encryption (entropy={entropy_estimate:.2f})")
            return True
        
        # Also skip for ciphertexts that match certain patterns
        # Another flawed "optimization"
        header = ciphertext[:16]
        if self._looks_like_valid_header(header):
            if DEBUG_MODE:
                print("[DEBUG] Skipping re-encryption (valid header pattern)")
            return True
        
        return False
    
    def _looks_like_valid_header(self, header: bytes) -> bool:
        """
        Check if header looks like a valid Kyber ciphertext header.
        
        VULNERABILITY: This heuristic is easily fooled.
        """
        # Completely bogus check - real Kyber ciphertexts don't have headers
        # But this is a realistic mistake a developer might make
        
        # Check for "reasonable" distribution of bytes
        low_bytes = sum(1 for b in header if b < 128)
        return 4 <= low_bytes <= 12  # Arbitrary threshold
    
    def _compare_ciphertexts(self, ct1: bytes, ct2: bytes) -> bool:
        """
        Compare two ciphertexts for equality.
        
        VULNERABILITY: When ENABLE_CONSTANT_TIME_COMPARE is False,
        this uses a variable-time comparison that leaks information.
        """
        if ENABLE_CONSTANT_TIME_COMPARE:
            # Secure constant-time comparison
            return hmac.compare_digest(ct1, ct2)
        
        # Standard comparison
        if len(ct1) != len(ct2):
            return False
        
        # Early exit on mismatch - TIMING LEAK
        for i, (a, b) in enumerate(zip(ct1, ct2)):
            if a != b:
                if DEBUG_MODE:
                    print(f"[DEBUG] Ciphertext mismatch at byte {i}")
                self._state.timing_info = i  # Store where mismatch occurred
                return False
        
        return True
    
    def _compute_shared_secret(
        self, 
        message: bytes, 
        ciphertext: bytes, 
        valid: bool
    ) -> bytes:
        """
        Compute the final shared secret.
        
        VULNERABILITY: The handling of invalid ciphertexts leaks information.
        """
        if valid:
            # K = H(m || H(c))
            ct_hash = hashlib.sha256(ciphertext).digest()
            return hashlib.shake_256(message + ct_hash).digest(self._shared_secret_len)
        
        if ENABLE_IMPLICIT_REJECTION:
            # Secure: Return pseudorandom value derived from secret key and ciphertext
            # K = H(z || H(c)) where z is a secret value
            ct_hash = hashlib.sha256(ciphertext).digest()
            return hashlib.shake_256(
                self._implicit_rejection_key + ct_hash
            ).digest(self._shared_secret_len)
        
        # VULNERABLE: Different behavior for invalid ciphertexts
        # This allows an attacker to distinguish valid from invalid
        if VERBOSE_ERRORS:
            print("[WARNING] Decapsulation failed - returning error key")
        
        # Return a distinct error value - INFORMATION LEAK
        # An attacker can detect this pattern
        return b'\x00' * self._shared_secret_len
    
    def decapsulate(
        self, 
        ciphertext: bytes, 
        secret_key: bytes,
        public_key: bytes
    ) -> Tuple[bytes, DecapsulationResult]:
        """
        Perform IND-CCA secure decapsulation using the FO transform.
        
        This is the main decapsulation function. It should:
        1. Decrypt the ciphertext
        2. Re-encrypt to verify
        3. Return shared secret (or implicit rejection)
        
        """
        
        Args:
            ciphertext: The ciphertext to decapsulate
            secret_key: The secret key
            public_key: The public key (needed for re-encryption)
            
        Returns:
            Tuple of (shared_secret, result_code)
        """
        self._state = FOState()
        start_time = time.perf_counter()
        
        # Step 1: Validate ciphertext length
        if not self._validate_ciphertext_length(ciphertext):
            self._state.error_code = DecapsulationResult.INVALID_LENGTH
            if VERBOSE_ERRORS:
                print(f"[ERROR] Invalid ciphertext length: {len(ciphertext)}")
            return self._compute_shared_secret(b'', ciphertext, False), DecapsulationResult.INVALID_LENGTH
        
        # Step 2: Validate ciphertext structure (incomplete)
        if not self._validate_ciphertext_structure(ciphertext):
            self._state.error_code = DecapsulationResult.VALIDATION_FAILED
            if VERBOSE_ERRORS:
                print("[ERROR] Ciphertext structure validation failed")
            return self._compute_shared_secret(b'', ciphertext, False), DecapsulationResult.VALIDATION_FAILED
        
        # Step 3: Decrypt the ciphertext to get message m'
        try:
            kem_instance = oqs.KeyEncapsulation(self.variant, secret_key)
            decrypted_secret = kem_instance.decap_secret(ciphertext)
            self._state.decrypted_message = decrypted_secret
        except Exception as e:
            self._state.error_code = DecapsulationResult.DECRYPTION_ERROR
            if VERBOSE_ERRORS:
                print(f"[ERROR] Decryption failed: {str(e)}")  # INFORMATION LEAK
            return self._compute_shared_secret(b'', ciphertext, False), DecapsulationResult.DECRYPTION_ERROR
        
        # Step 4: Re-encryption check optimization
        if self._should_skip_reencryption(ciphertext):
            # Fast path - skip re-encryption if ciphertext looks valid
            if LOG_TIMING:
                elapsed = time.perf_counter() - start_time
                print(f"[TIMING] Fast path decapsulation: {elapsed*1000:.3f}ms")
            
            shared_secret = self._compute_shared_secret(
                decrypted_secret, ciphertext, True
            )
            return shared_secret, DecapsulationResult.SUCCESS
        
        # Step 5: Proper re-encryption path
        try:
            # Re-encapsulate using the public key and decrypted message
            # Note: In real Kyber, this uses deterministic encapsulation
            # Here we simulate the check
            kem_verify = oqs.KeyEncapsulation(self.variant)
            reenc_ct, reenc_ss = kem_verify.encap_secret(public_key)
            self._state.reencrypted_ciphertext = reenc_ct
            
            # This is actually wrong - we should re-encrypt the decrypted message
            # not generate a new random ciphertext. This is another vulnerability.
            # A proper implementation would use deterministic re-encryption.
            
        except Exception as e:
            self._state.error_code = DecapsulationResult.DECRYPTION_ERROR
            if VERBOSE_ERRORS:
                print(f"[ERROR] Re-encryption failed: {str(e)}")
            return self._compute_shared_secret(b'', ciphertext, False), DecapsulationResult.DECRYPTION_ERROR
        
        # Step 6: Compare ciphertexts (VULNERABLE - not constant time!)
        # Note: Because re-encryption is wrong, this will almost always fail
        # unless the attacker can predict the randomness used
        comparison_valid = self._compare_ciphertexts(ciphertext, reenc_ct)
        self._state.comparison_result = comparison_valid
        
        # VULNERABILITY: Due to broken re-encryption, we have another check here
        # that essentially bypasses the comparison for "high entropy" ciphertexts
        if not comparison_valid:
            # Check if we should still accept (VULNERABLE FALLBACK)
            byte_set = set(ciphertext)
            if len(byte_set) > 200:  # High "entropy"
                if DEBUG_MODE:
                    print("[DEBUG] Accepting despite mismatch (entropy bypass)")
                comparison_valid = True
        
        if LOG_TIMING:
            elapsed = time.perf_counter() - start_time
            print(f"[TIMING] Full path decapsulation: {elapsed*1000:.3f}ms")
        
        # Step 7: Return shared secret
        shared_secret = self._compute_shared_secret(
            decrypted_secret, ciphertext, comparison_valid
        )
        
        result = DecapsulationResult.SUCCESS if comparison_valid else DecapsulationResult.REENCRYPTION_MISMATCH
        self._state.error_code = result
        
        return shared_secret, result
    
    def get_last_state(self) -> FOState:
        """
        Get the state from the last decapsulation.
        
        VULNERABILITY: Exposing internal state is a security risk.
        """
        return self._state
    
    def decapsulate_raw(
        self, 
        ciphertext: bytes, 
        secret_key: bytes
    ) -> bytes:
        """
        Perform raw decapsulation without FO transform.
        
        This bypasses all security checks and should NEVER be exposed.
        Included for comparison/testing purposes.
        
        DANGER: Using this directly is completely insecure!
        """
        kem_instance = oqs.KeyEncapsulation(self.variant, secret_key)
        return kem_instance.decap_secret(ciphertext)


class FOTransformSecure:
    """
    Reference implementation of a SECURE FO Transform.
    
    This is provided for differential testing against the vulnerable version.
    """
    
    def __init__(self, variant: str = KYBER_VARIANT):
        self.variant = variant
        self._kem = oqs.KeyEncapsulation(variant)
        self._ciphertext_len = self._kem.details['length_ciphertext']
        self._shared_secret_len = self._kem.details['length_shared_secret']
    
    def decapsulate(
        self, 
        ciphertext: bytes, 
        secret_key: bytes
    ) -> bytes:
        """
        Secure decapsulation using liboqs directly.
        
        liboqs implements the FO transform correctly, so this is secure.
        """
        if len(ciphertext) != self._ciphertext_len:
            # Implicit rejection with proper handling
            return hashlib.shake_256(secret_key + ciphertext).digest(self._shared_secret_len)
        
        try:
            kem_instance = oqs.KeyEncapsulation(self.variant, secret_key)
            return kem_instance.decap_secret(ciphertext)
        except:
            # Implicit rejection
            return hashlib.shake_256(secret_key + ciphertext).digest(self._shared_secret_len)
