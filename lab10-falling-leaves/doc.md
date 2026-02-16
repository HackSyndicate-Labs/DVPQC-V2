# SPH-01 "Falling Leaves" — Technical Documentation

## Vulnerability: Tree Traversal Weakness

### Mechanism

The `tree_monitor.c` module implements a "tree health monitor" that decomposes
every SPHINCS+ signature into its internal components and writes them to a
structured binary diagnostic file (`data/diagnostics/tree_health.bin`).

After each call to `spx_sign()`, the service calls:
1. `record_fors_data(sig)` — Extracts all 33 FORS authentication paths
2. `record_hypertree_data(sig, siglen)` — Extracts all 22 layers of
   WOTS+ chain values and Merkle authentication paths

### What Gets Leaked

| Component | Bytes/Entry | Entries/Sig | Purpose |
|-----------|-------------|-------------|---------|
| FORS auth paths | 96 | 33 | Sibling nodes in FORS trees |
| WOTS+ chains | 560 | 22 | Hash chain intermediate values |
| Merkle auth paths | 48 | 22 | Sibling nodes in hypertree subtrees |

**Total per signature:** 77 entries, ~15,576 bytes of internal tree data.

### Binary Protocol

```
File Header (26 bytes):
  magic:     uint32  (0x54524545 = "TREE")
  version:   uint16  (0x0002)
  entries:   uint32  (total entry count)
  pk_hash:   byte[16]

Entry Header (26 bytes):
  magic:     uint32
  version:   uint16
  type:      uint8   (0x01=AUTH, 0x02=FORS, 0x03=WOTS)
  layer:     uint8   (hypertree layer or 0xFF for FORS)
  tree_addr: uint64
  leaf_idx:  uint32
  timestamp: uint32
  data_len:  uint16

Entry Data: [data_len bytes]
```

### Exploitation
The diagnostic file contains enough latent information to reconstruct the full signature if one knows the structure.

### Remediation

1. **Remove the tree monitor entirely** — no production system needs to
   dump internal signature components
2. If monitoring is needed, hash the nodes before logging (don't log raw values)
3. Restrict access to diagnostic files (permissions, encryption)
4. Monitor for unauthorized reads of the diagnostic directory
