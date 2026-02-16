#!/usr/bin/env python3
"""
Fuzz Decapsulation - Main Fuzzing Harness
==========================================

This harness fuzzes the vulnerable decapsulation implementation
using Atheris (Google's coverage-guided Python fuzzer).

Usage:
    # Basic fuzzing
    python fuzz_decaps.py -max_len=1088

    # With corpus
    python fuzz_decaps.py ../corpus/seed_ciphertexts/ -max_len=1088

    # Extended run
    python fuzz_decaps.py -max_len=1088 -runs=1000000 -jobs=4
"""

import sys
import os

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import atheris

# Must import atheris first, then patch modules
with atheris.instrument_imports():
    import oqs
    from src.fo_transform import FOTransform, FOTransformSecure, DecapsulationResult
    from src.echo_chamber import EchoChamber, EchoChamberFactory


# Global state - initialized once for performance
_kem = None
_public_key = None
_secret_key = None
_transform_vuln = None
_transform_secure = None
_initialized = False


def initialize():
    """Initialize global state for fuzzing."""
    global _kem, _public_key, _secret_key, _transform_vuln, _transform_secure, _initialized
    
    if _initialized:
        return
    
    # Generate a fixed keypair for consistent testing
    _kem = oqs.KeyEncapsulation("Kyber768")
    _public_key = _kem.generate_keypair()
    _secret_key = _kem.export_secret_key()
    
    # Create transform instances
    _transform_vuln = FOTransform("Kyber768")
    _transform_secure = FOTransformSecure("Kyber768")
    
    _initialized = True
    print("[FUZZ] Initialized with Kyber768 keypair")


def test_one_input(data: bytes) -> None:
    """
    Test function called by the fuzzer for each input.
    
    This function:
    1. Ensures correct ciphertext length (or returns early)
    2. Calls the vulnerable decapsulation
    3. Optionally compares with secure implementation
    4. Checks for interesting behaviors
    
    Args:
        data: Fuzzed input bytes
    """
    initialize()
    
    # Only test correct-length ciphertexts
    # This focuses fuzzing on meaningful inputs
    if len(data) != 1088:
        return
    
    ciphertext = data
    
    try:
        # Call vulnerable implementation
        ss_vuln, result_vuln = _transform_vuln.decapsulate(
            ciphertext, 
            _secret_key, 
            _public_key
        )
        
        # Call secure implementation
        ss_secure = _transform_secure.decapsulate(ciphertext, _secret_key)
        
        # Check for differential behavior (THE VULNERABILITY!)
        if ss_vuln != ss_secure:
            # This is what we're looking for!
            # The vulnerable implementation produced a different result
            
            # Save this interesting input
            with open(f'diff_found_{hash(ciphertext) & 0xFFFFFFFF:08x}.bin', 'wb') as f:
                f.write(ciphertext)
            
            # Trigger a "crash" to make the fuzzer save this
            raise ValueError(f"DIFFERENTIAL FOUND! vuln_result={result_vuln.name}")
        
        # Check for timing anomalies (implicit in state)
        state = _transform_vuln.get_last_state()
        if state.timing_info is not None:
            # Variable timing detected - potential side channel
            pass  # This is expected with the vulnerable impl
            
    except ValueError as e:
        # Re-raise differential findings
        if "DIFFERENTIAL" in str(e):
            raise
        # Other ValueErrors are expected for malformed inputs
        pass
    except Exception as e:
        # Unexpected exceptions are interesting
        print(f"[FUZZ] Unexpected error: {type(e).__name__}: {e}")
        raise


def test_one_input_fast(data: bytes) -> None:
    """
    Fast test function - only tests vulnerable implementation.
    
    Use this for initial corpus discovery.
    """
    initialize()
    
    if len(data) != 1088:
        return
    
    try:
        ss, result = _transform_vuln.decapsulate(data, _secret_key, _public_key)
    except Exception:
        pass


def test_one_input_with_length_variants(data: bytes) -> None:
    """
    Test function that also tests length variants.
    
    This can find edge cases in length validation.
    """
    initialize()
    
    # Test exact input
    try:
        if len(data) == 1088:
            ss, result = _transform_vuln.decapsulate(data, _secret_key, _public_key)
    except Exception:
        pass
    
    # Test padded to correct length
    if len(data) < 1088:
        padded = data + b'\x00' * (1088 - len(data))
        try:
            ss, result = _transform_vuln.decapsulate(padded, _secret_key, _public_key)
        except Exception:
            pass
    
    # Test truncated
    if len(data) > 1088:
        truncated = data[:1088]
        try:
            ss, result = _transform_vuln.decapsulate(truncated, _secret_key, _public_key)
        except Exception:
            pass


def main():
    """Main entry point for fuzzing."""
    print("=" * 60)
    print("Crystal Echo Decapsulation Fuzzer")
    print("=" * 60)
    print()
    print("Target: FOTransform.decapsulate")
    print("Looking for: Differential behavior vs secure implementation")
    print()
    
    # Initialize before fuzzing
    initialize()
    
    # Generate a valid ciphertext for reference
    ct, ss = _kem.encap_secret(_public_key)
    print(f"Reference ciphertext: {ct[:16].hex()}...")
    print(f"Expected shared secret: {ss.hex()}")
    print()
    
    # Start fuzzing
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
