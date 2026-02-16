#!/usr/bin/env python3
"""
Generate Seeds - Create Initial Fuzzing Corpus
===============================================

This script generates an initial corpus of seed ciphertexts
for fuzzing the Crystal Echo system.

Usage:
    python generate_seeds.py [output_dir]
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oqs


def generate_seeds(output_dir: str = "corpus/seed_ciphertexts"):
    """Generate seed ciphertexts for fuzzing corpus."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Generating seeds in {output_dir}/")
    
    # Initialize Kyber
    kem = oqs.KeyEncapsulation("Kyber768")
    pk = kem.generate_keypair()
    
    seeds = []
    
    # Seed 1: Valid ciphertext
    ct, _ = kem.encap_secret(pk)
    seeds.append(("valid_ct.bin", ct, "Valid ciphertext from proper encapsulation"))
    
    # Seed 2: All zeros
    seeds.append(("zero_ct.bin", b'\x00' * 1088, "All zero bytes"))
    
    # Seed 3: All ones (0xFF)
    seeds.append(("max_ct.bin", b'\xFF' * 1088, "All 0xFF bytes"))
    
    # Seed 4: Random bytes
    seeds.append(("random_ct.bin", os.urandom(1088), "Random bytes"))
    
    # Seed 5: High entropy (unique bytes)
    high_entropy = bytes([i % 256 for i in range(1088)])
    seeds.append(("high_entropy_ct.bin", high_entropy, "High entropy - sequential bytes mod 256"))
    
    # Seed 6: Valid CT with single bit flip at start
    flipped_start = bytearray(ct)
    flipped_start[0] ^= 0x01
    seeds.append(("flipped_start_ct.bin", bytes(flipped_start), "Valid CT with bit flip at position 0"))
    
    # Seed 7: Valid CT with single bit flip in middle
    flipped_mid = bytearray(ct)
    flipped_mid[544] ^= 0x80
    seeds.append(("flipped_mid_ct.bin", bytes(flipped_mid), "Valid CT with bit flip at position 544"))
    
    # Seed 8: Valid CT with single bit flip at end
    flipped_end = bytearray(ct)
    flipped_end[-1] ^= 0x01
    seeds.append(("flipped_end_ct.bin", bytes(flipped_end), "Valid CT with bit flip at end"))
    
    # Seed 9: Valid CT with u0 zeroed
    u0_zero = bytearray(ct)
    u0_zero[:320] = b'\x00' * 320
    seeds.append(("u0_zero_ct.bin", bytes(u0_zero), "Valid CT with u[0] component zeroed"))
    
    # Seed 10: Valid CT with v zeroed
    v_zero = bytearray(ct)
    v_zero[960:] = b'\x00' * 128
    seeds.append(("v_zero_ct.bin", bytes(v_zero), "Valid CT with v component zeroed"))
    
    # Seed 11: Alternating 0x00 and 0xFF
    alternating = bytes([0x00 if i % 2 == 0 else 0xFF for i in range(1088)])
    seeds.append(("alternating_ct.bin", alternating, "Alternating 0x00/0xFF pattern"))
    
    # Seed 12: Pattern designed to trigger header check
    # Header check looks for 4-12 bytes < 128 in first 16 bytes
    header_trigger = bytearray(os.urandom(1088))
    header_trigger[:8] = b'\x7F' * 8  # 8 bytes < 128
    header_trigger[8:16] = b'\x80' * 8  # 8 bytes >= 128
    seeds.append(("header_trigger_ct.bin", bytes(header_trigger), "Designed to trigger header pattern check"))
    
    # Seed 13: Very high entropy (>200 unique bytes) - targets entropy bypass
    entropy_bypass = bytearray(1088)
    for i in range(256):
        if i < 1088:
            entropy_bypass[i] = i
        if 256 + i < 1088:
            entropy_bypass[256 + i] = (i + 37) % 256
        if 512 + i < 1088:
            entropy_bypass[512 + i] = (i + 73) % 256
        if 768 + i < 1088:
            entropy_bypass[768 + i] = (i + 137) % 256
    seeds.append(("entropy_bypass_ct.bin", bytes(entropy_bypass), "High entropy to trigger entropy bypass"))
    
    # Seed 14: Boundary values pattern
    boundary = bytearray(1088)
    for i in range(0, 1088, 4):
        boundary[i] = 0
        if i + 1 < 1088:
            boundary[i + 1] = 127
        if i + 2 < 1088:
            boundary[i + 2] = 128
        if i + 3 < 1088:
            boundary[i + 3] = 255
    seeds.append(("boundary_ct.bin", bytes(boundary), "Boundary values pattern (0, 127, 128, 255)"))
    
    # Seed 15: Multiple valid ciphertexts concatenated then truncated
    ct2, _ = kem.encap_secret(pk)
    mixed = (ct + ct2)[:1088]
    seeds.append(("mixed_valid_ct.bin", mixed, "Two valid CTs concatenated and truncated"))
    
    # Write all seeds
    print(f"\n[*] Writing {len(seeds)} seed files:")
    for filename, data, description in seeds:
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(data)
        
        entropy = len(set(data))
        print(f"  {filename:25s} ({entropy:3d} unique bytes) - {description}")
    
    # Write metadata
    metadata_path = os.path.join(output_dir, "README.txt")
    with open(metadata_path, 'w') as f:
        f.write("Fuzzing Corpus Seeds for Crystal Echo Lab\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated with Kyber768\n")
        f.write(f"Ciphertext length: 1088 bytes\n\n")
        f.write("Seeds:\n\n")
        for filename, data, description in seeds:
            entropy = len(set(data))
            f.write(f"- {filename}\n")
            f.write(f"  Entropy: {entropy} unique bytes\n")
            f.write(f"  Description: {description}\n\n")
    
    print(f"\n[*] Wrote metadata to {metadata_path}")
    print(f"[*] Corpus generation complete!")
    
    return len(seeds)


def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "corpus/seed_ciphertexts"
    
    print("=" * 60)
    print("Crystal Echo Seed Generator")
    print("=" * 60)
    
    num_seeds = generate_seeds(output_dir)
    
    print(f"\n[*] Generated {num_seeds} seeds in {output_dir}/")
    print("[*] Use these as initial corpus for fuzzing")


if __name__ == "__main__":
    main()
