#!/usr/bin/env python3
"""
Differential Fuzzing - Compare Vulnerable vs Secure Implementation
===================================================================

This harness performs differential fuzzing: comparing the vulnerable
FOTransform against the secure FOTransformSecure (which uses liboqs
directly).

Any input that causes different outputs between the implementations
indicates a vulnerability.

Usage:
    python differential_fuzz.py -max_len=1088 -runs=100000
"""

import sys
import os
import time
import json
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import atheris

with atheris.instrument_imports():
    import oqs
    from src.fo_transform import FOTransform, FOTransformSecure, DecapsulationResult
    from src.echo_chamber import EchoChamber, EchoChamberFactory


@dataclass
class DifferentialResult:
    """Record of a differential finding."""
    timestamp: str
    ciphertext_hex: str
    ciphertext_entropy: int
    vuln_result: str
    vuln_ss_hex: str
    secure_ss_hex: str
    timing_diff_ns: int
    notes: str


class DifferentialFuzzer:
    """
    Differential fuzzer comparing vulnerable and secure implementations.
    """
    
    def __init__(self):
        """Initialize the differential fuzzer."""
        self.kem = oqs.KeyEncapsulation("Kyber768")
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        
        self.transform_vuln = FOTransform("Kyber768")
        self.transform_secure = FOTransformSecure("Kyber768")
        
        # Generate reference ciphertext
        self.ref_ct, self.ref_ss = self.kem.encap_secret(self.public_key)
        
        # Statistics
        self.total_tests = 0
        self.differentials_found = 0
        self.findings: list = []
        
        print("[DiffFuzz] Initialized")
        print(f"[DiffFuzz] Reference ciphertext: {self.ref_ct[:16].hex()}...")
    
    def test_ciphertext(self, ciphertext: bytes) -> Optional[DifferentialResult]:
        """
        Test a ciphertext for differential behavior.
        
        Args:
            ciphertext: The ciphertext to test
            
        Returns:
            DifferentialResult if a difference is found, None otherwise
        """
        self.total_tests += 1
        
        if len(ciphertext) != 1088:
            return None
        
        # Time vulnerable implementation
        start_vuln = time.perf_counter_ns()
        try:
            ss_vuln, result_vuln = self.transform_vuln.decapsulate(
                ciphertext, self.secret_key, self.public_key
            )
        except Exception as e:
            ss_vuln = None
            result_vuln = f"EXCEPTION: {type(e).__name__}"
        end_vuln = time.perf_counter_ns()
        
        # Time secure implementation
        start_secure = time.perf_counter_ns()
        try:
            ss_secure = self.transform_secure.decapsulate(
                ciphertext, self.secret_key
            )
        except Exception as e:
            ss_secure = None
        end_secure = time.perf_counter_ns()
        
        # Compare results
        if ss_vuln != ss_secure:
            self.differentials_found += 1
            
            result = DifferentialResult(
                timestamp=datetime.now().isoformat(),
                ciphertext_hex=ciphertext.hex(),
                ciphertext_entropy=len(set(ciphertext)),
                vuln_result=result_vuln.name if isinstance(result_vuln, DecapsulationResult) else str(result_vuln),
                vuln_ss_hex=ss_vuln.hex() if ss_vuln else "None",
                secure_ss_hex=ss_secure.hex() if ss_secure else "None",
                timing_diff_ns=(end_vuln - start_vuln) - (end_secure - start_secure),
                notes=self._analyze_ciphertext(ciphertext),
            )
            
            self.findings.append(result)
            return result
        
        return None
    
    def _analyze_ciphertext(self, ct: bytes) -> str:
        """Analyze a ciphertext to understand why it triggered a differential."""
        notes = []
        
        entropy = len(set(ct))
        notes.append(f"entropy={entropy}")
        
        if entropy > 200:
            notes.append("HIGH_ENTROPY_BYPASS")
        
        # Check component patterns
        u0 = ct[:320]
        u1 = ct[320:640]
        u2 = ct[640:960]
        v = ct[960:]
        
        if all(b == 0 for b in u0):
            notes.append("u0_zero")
        if all(b == 0 for b in u1):
            notes.append("u1_zero")
        if all(b == 0 for b in u2):
            notes.append("u2_zero")
        if all(b == 0 for b in v):
            notes.append("v_zero")
        
        # Check for header pattern
        header = ct[:16]
        low_bytes = sum(1 for b in header if b < 128)
        if 4 <= low_bytes <= 12:
            notes.append("HEADER_PATTERN_MATCH")
        
        return ", ".join(notes)
    
    def print_stats(self):
        """Print fuzzing statistics."""
        print(f"\n[Stats] Tests: {self.total_tests}, Differentials: {self.differentials_found}")
        if self.differentials_found > 0:
            print(f"[Stats] Rate: {self.differentials_found / self.total_tests * 100:.2f}%")
    
    def save_findings(self, filename: str = "differential_findings.json"):
        """Save findings to a JSON file."""
        with open(filename, 'w') as f:
            json.dump([asdict(r) for r in self.findings], f, indent=2)
        print(f"[*] Saved {len(self.findings)} findings to {filename}")


# Global fuzzer instance
_fuzzer: Optional[DifferentialFuzzer] = None


def initialize():
    """Initialize the global fuzzer."""
    global _fuzzer
    if _fuzzer is None:
        _fuzzer = DifferentialFuzzer()


def test_one_input(data: bytes) -> None:
    """Atheris test function."""
    initialize()
    
    # Ensure correct length
    if len(data) < 1088:
        data = data + os.urandom(1088 - len(data))
    elif len(data) > 1088:
        data = data[:1088]
    
    result = _fuzzer.test_ciphertext(data)
    
    if result:
        print(f"\n[!] DIFFERENTIAL #{_fuzzer.differentials_found}")
        print(f"    Entropy: {result.ciphertext_entropy}")
        print(f"    Vuln result: {result.vuln_result}")
        print(f"    Notes: {result.notes}")
        
        # Save this ciphertext
        filename = f"diff_{_fuzzer.differentials_found:04d}.bin"
        with open(filename, 'wb') as f:
            f.write(bytes.fromhex(result.ciphertext_hex))
        
        # Raise to make fuzzer save the input
        raise AssertionError(f"Differential found: {result.notes}")
    
    # Periodic stats
    if _fuzzer.total_tests % 10000 == 0:
        _fuzzer.print_stats()


def run_targeted_tests():
    """Run targeted tests before fuzzing."""
    initialize()
    
    print("\n[*] Running targeted differential tests...")
    
    # Test 1: Valid ciphertext (should match)
    result = _fuzzer.test_ciphertext(_fuzzer.ref_ct)
    print(f"  Valid CT: {'DIFF' if result else 'OK'}")
    
    # Test 2: High entropy random (may trigger bypass)
    high_entropy = os.urandom(1088)
    result = _fuzzer.test_ciphertext(high_entropy)
    print(f"  High entropy random: {'DIFF' if result else 'OK'}")
    
    # Test 3: Valid CT with bit flip
    flipped = bytearray(_fuzzer.ref_ct)
    flipped[500] ^= 0x01
    result = _fuzzer.test_ciphertext(bytes(flipped))
    print(f"  Bit-flipped valid CT: {'DIFF' if result else 'OK'}")
    
    # Test 4: All zeros
    result = _fuzzer.test_ciphertext(b'\x00' * 1088)
    print(f"  All zeros: {'DIFF' if result else 'OK'}")
    
    # Test 5: Crafted high-entropy
    crafted = bytes([i % 256 for i in range(1088)])
    result = _fuzzer.test_ciphertext(crafted)
    print(f"  Crafted high-entropy: {'DIFF' if result else 'OK'}")
    
    # Test 6: Valid CT with high-entropy replacement
    mixed = _fuzzer.ref_ct[:500] + os.urandom(588)
    result = _fuzzer.test_ciphertext(mixed)
    print(f"  Mixed valid/random: {'DIFF' if result else 'OK'}")
    
    _fuzzer.print_stats()
    
    if _fuzzer.differentials_found > 0:
        _fuzzer.save_findings()


def main():
    """Main entry point."""
    print("=" * 60)
    print("Crystal Echo Differential Fuzzer")
    print("=" * 60)
    print()
    print("Comparing: FOTransform (vulnerable) vs FOTransformSecure")
    print("Goal: Find inputs that produce different outputs")
    print()
    
    # Run targeted tests first
    run_targeted_tests()
    
    print("\n[*] Starting continuous differential fuzzing...")
    print("[*] Press Ctrl+C to stop\n")
    
    # Start atheris fuzzing
    atheris.Setup(sys.argv, test_one_input)
    
    try:
        atheris.Fuzz()
    except KeyboardInterrupt:
        print("\n[*] Fuzzing stopped by user")
        if _fuzzer:
            _fuzzer.print_stats()
            if _fuzzer.differentials_found > 0:
                _fuzzer.save_findings()


if __name__ == "__main__":
    main()
