Fuzzing Corpus Seeds for Crystal Echo Lab
==================================================

Generated with Kyber768
Ciphertext length: 1088 bytes

Seeds:

- valid_ct.bin
  Entropy: 253 unique bytes
  Description: Valid ciphertext from proper encapsulation

- zero_ct.bin
  Entropy: 1 unique bytes
  Description: All zero bytes

- max_ct.bin
  Entropy: 1 unique bytes
  Description: All 0xFF bytes

- random_ct.bin
  Entropy: 253 unique bytes
  Description: Random bytes

- high_entropy_ct.bin
  Entropy: 256 unique bytes
  Description: High entropy - sequential bytes mod 256

- flipped_start_ct.bin
  Entropy: 253 unique bytes
  Description: Valid CT with bit flip at position 0

- flipped_mid_ct.bin
  Entropy: 253 unique bytes
  Description: Valid CT with bit flip at position 544

- flipped_end_ct.bin
  Entropy: 253 unique bytes
  Description: Valid CT with bit flip at end

- u0_zero_ct.bin
  Entropy: 238 unique bytes
  Description: Valid CT with u[0] component zeroed

- v_zero_ct.bin
  Entropy: 249 unique bytes
  Description: Valid CT with v component zeroed

- alternating_ct.bin
  Entropy: 2 unique bytes
  Description: Alternating 0x00/0xFF pattern

- header_trigger_ct.bin
  Entropy: 252 unique bytes
  Description: Designed to trigger header pattern check

- entropy_bypass_ct.bin
  Entropy: 256 unique bytes
  Description: High entropy to trigger entropy bypass

- boundary_ct.bin
  Entropy: 4 unique bytes
  Description: Boundary values pattern (0, 127, 128, 255)

- mixed_valid_ct.bin
  Entropy: 253 unique bytes
  Description: Two valid CTs concatenated and truncated

