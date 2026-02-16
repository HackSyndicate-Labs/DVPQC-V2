#!/usr/bin/env python3
"""
Fuzz Ciphertext - Structure-Aware Ciphertext Fuzzing
=====================================================

This harness performs structure-aware fuzzing of Kyber ciphertexts,
understanding the internal structure to generate more meaningful mutations.

Kyber768 Ciphertext Structure (1088 bytes total):
- u: 960 bytes (3 polynomials × 320 bytes each, compressed)
- v: 128 bytes (1 polynomial, compressed)

The compression uses du=10 bits for u and dv=4 bits for v.
"""

import sys
import os
import struct
import random
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import atheris

with atheris.instrument_imports():
    import oqs
    from src.fo_transform import FOTransform, FOTransformSecure, DecapsulationResult
    from src.echo_chamber import EchoChamberFactory


# Kyber768 constants
KYBER_N = 256  # Polynomial degree
KYBER_K = 3    # Module rank
KYBER_DU = 10  # Compression bits for u
KYBER_DV = 4   # Compression bits for v
KYBER_CT_U_BYTES = 960  # 3 * 320
KYBER_CT_V_BYTES = 128
KYBER_CT_BYTES = 1088


# Global state
_kem = None
_public_key = None
_secret_key = None
_transform_vuln = None
_transform_secure = None
_valid_ciphertext = None
_valid_shared_secret = None


def initialize():
    """Initialize fuzzing state."""
    global _kem, _public_key, _secret_key, _transform_vuln, _transform_secure
    global _valid_ciphertext, _valid_shared_secret
    
    if _kem is not None:
        return
    
    _kem = oqs.KeyEncapsulation("Kyber768")
    _public_key = _kem.generate_keypair()
    _secret_key = _kem.export_secret_key()
    
    _transform_vuln = FOTransform("Kyber768")
    _transform_secure = FOTransformSecure("Kyber768")
    
    # Generate a valid ciphertext for mutations
    _valid_ciphertext, _valid_shared_secret = _kem.encap_secret(_public_key)
    
    print(f"[FUZZ] Initialized with valid ciphertext template")


class CiphertextMutator:
    """
    Structure-aware mutator for Kyber ciphertexts.
    
    Generates mutations that are more likely to trigger interesting
    behavior in the decapsulation code.
    """
    
    def __init__(self, base_ciphertext: bytes):
        """
        Initialize mutator with a base (valid) ciphertext.
        
        Args:
            base_ciphertext: A valid Kyber ciphertext to mutate
        """
        self.base = bytearray(base_ciphertext)
        self.u_section = self.base[:KYBER_CT_U_BYTES]
        self.v_section = self.base[KYBER_CT_U_BYTES:]
    
    def flip_bit(self, position: int) -> bytes:
        """Flip a single bit at the given position."""
        result = bytearray(self.base)
        byte_pos = position // 8
        bit_pos = position % 8
        if byte_pos < len(result):
            result[byte_pos] ^= (1 << bit_pos)
        return bytes(result)
    
    def flip_random_bits(self, count: int) -> bytes:
        """Flip random bits in the ciphertext."""
        result = bytearray(self.base)
        for _ in range(count):
            pos = random.randint(0, len(result) * 8 - 1)
            byte_pos = pos // 8
            bit_pos = pos % 8
            result[byte_pos] ^= (1 << bit_pos)
        return bytes(result)
    
    def mutate_u_component(self, index: int, value: bytes) -> bytes:
        """
        Mutate a specific u polynomial component.
        
        Args:
            index: Which of the 3 polynomials (0-2)
            value: 320 bytes to replace with
        """
        result = bytearray(self.base)
        start = index * 320
        end = start + 320
        result[start:end] = value[:320].ljust(320, b'\x00')
        return bytes(result)
    
    def mutate_v_component(self, value: bytes) -> bytes:
        """Mutate the v component."""
        result = bytearray(self.base)
        result[KYBER_CT_U_BYTES:] = value[:KYBER_CT_V_BYTES].ljust(KYBER_CT_V_BYTES, b'\x00')
        return bytes(result)
    
    def zero_component(self, component: str) -> bytes:
        """Zero out a component (u0, u1, u2, or v)."""
        result = bytearray(self.base)
        if component == 'u0':
            result[0:320] = b'\x00' * 320
        elif component == 'u1':
            result[320:640] = b'\x00' * 320
        elif component == 'u2':
            result[640:960] = b'\x00' * 320
        elif component == 'v':
            result[960:] = b'\x00' * 128
        return bytes(result)
    
    def max_component(self, component: str) -> bytes:
        """Set a component to all 0xFF."""
        result = bytearray(self.base)
        if component == 'u0':
            result[0:320] = b'\xFF' * 320
        elif component == 'u1':
            result[320:640] = b'\xFF' * 320
        elif component == 'u2':
            result[640:960] = b'\xFF' * 320
        elif component == 'v':
            result[960:] = b'\xFF' * 128
        return bytes(result)
    
    def high_entropy_mutation(self) -> bytes:
        """
        Create a high-entropy ciphertext.
        
        This is designed to trigger the entropy bypass in the vulnerable code.
        """
        # Create ciphertext with >200 unique bytes
        result = bytearray(1088)
        for i in range(256):
            # Distribute unique bytes throughout
            positions = [i, i + 256, i + 512, i + 768]
            for pos in positions:
                if pos < 1088:
                    result[pos] = i
        return bytes(result)
    
    def boundary_mutation(self) -> bytes:
        """
        Create ciphertext with boundary values.
        
        Tests edge cases in coefficient handling.
        """
        result = bytearray(self.base)
        # Set some bytes to boundary values
        for i in range(0, 1088, 64):
            result[i] = 0
            if i + 1 < 1088:
                result[i + 1] = 255
            if i + 2 < 1088:
                result[i + 2] = 127
            if i + 3 < 1088:
                result[i + 3] = 128
        return bytes(result)


def generate_interesting_ciphertexts() -> List[bytes]:
    """
    Generate a set of interesting ciphertexts for fuzzing.
    
    Returns:
        List of potentially interesting ciphertext mutations
    """
    initialize()
    
    mutator = CiphertextMutator(_valid_ciphertext)
    ciphertexts = []
    
    # Valid ciphertext
    ciphertexts.append(_valid_ciphertext)
    
    # Single bit flips at interesting positions
    for pos in [0, 1, 7, 8, 319, 320, 639, 640, 959, 960, 1087]:
        ciphertexts.append(mutator.flip_bit(pos * 8))
    
    # Component-level mutations
    for comp in ['u0', 'u1', 'u2', 'v']:
        ciphertexts.append(mutator.zero_component(comp))
        ciphertexts.append(mutator.max_component(comp))
    
    # High entropy (targets bypass vulnerability)
    ciphertexts.append(mutator.high_entropy_mutation())
    
    # Boundary values
    ciphertexts.append(mutator.boundary_mutation())
    
    # Random mutations
    for num_bits in [1, 2, 4, 8, 16, 32]:
        ciphertexts.append(mutator.flip_random_bits(num_bits))
    
    # All zeros
    ciphertexts.append(b'\x00' * 1088)
    
    # All ones
    ciphertexts.append(b'\xFF' * 1088)
    
    # Random
    ciphertexts.append(os.urandom(1088))
    
    return ciphertexts


def test_one_input(data: bytes) -> None:
    """
    Atheris test function for structure-aware fuzzing.
    """
    initialize()
    
    if len(data) < 1088:
        # Pad short inputs
        data = data + b'\x00' * (1088 - len(data))
    elif len(data) > 1088:
        # Truncate long inputs
        data = data[:1088]
    
    try:
        # Test vulnerable implementation
        ss_vuln, result_vuln = _transform_vuln.decapsulate(
            data, _secret_key, _public_key
        )
        
        # Test secure implementation
        ss_secure = _transform_secure.decapsulate(data, _secret_key)
        
        # Check for differential
        if ss_vuln != ss_secure:
            # Found a discrepancy!
            print(f"\n[!] DIFFERENTIAL FOUND!")
            print(f"    Input entropy: {len(set(data))} unique bytes")
            print(f"    Vulnerable result: {result_vuln.name}")
            print(f"    Vulnerable SS: {ss_vuln[:8].hex()}...")
            print(f"    Secure SS: {ss_secure[:8].hex()}...")
            
            # Save the interesting input
            filename = f"differential_{hash(data) & 0xFFFFFFFF:08x}.bin"
            with open(filename, 'wb') as f:
                f.write(data)
            print(f"    Saved to: {filename}")
            
            # Raise to mark as crash
            raise AssertionError("Differential behavior detected!")
            
    except AssertionError:
        raise
    except Exception as e:
        # Log but don't crash on expected exceptions
        pass


def main():
    """Main entry point."""
    print("=" * 60)
    print("Crystal Echo Structure-Aware Ciphertext Fuzzer")
    print("=" * 60)
    
    initialize()
    
    # Generate and test interesting ciphertexts first
    print("\n[*] Testing pre-generated interesting ciphertexts...")
    interesting = generate_interesting_ciphertexts()
    
    for i, ct in enumerate(interesting):
        try:
            test_one_input(ct)
        except AssertionError as e:
            print(f"[!] Found issue in ciphertext {i}: {e}")
    
    print(f"\n[*] Tested {len(interesting)} pre-generated ciphertexts")
    print("[*] Starting continuous fuzzing...\n")
    
    # Start atheris fuzzing
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
