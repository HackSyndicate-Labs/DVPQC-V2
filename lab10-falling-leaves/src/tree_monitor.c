/**
 * Tree Health Monitor — Merkle Tree Diagnostics
 * ================================================
 * Monitors the internal state of the SPHINCS+ hypertree
 * for performance analysis and root integrity verification.
 *
 * Records structural metrics from each signing operation
 * to detect tree degradation and optimize path caching.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) mkdir(p)
#else
#define MKDIR(p) mkdir(p, 0755)
#endif
#include "lab10.h"

/* ── Module state ─────────────────────────────────────── */
static FILE *g_diag_file = NULL;
static uint32_t g_entry_count = 0;
static uint8_t g_pk_hash[16];

/* ── Internal helpers ─────────────────────────────────── */

static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        MKDIR(path);
    }
}

static void compute_pk_hash(const uint8_t *pk) {
    /*
     * Simple hash of the public key for identification.
     * Uses a basic XOR-fold since we just need a tag.
     */
    memset(g_pk_hash, 0, 16);
    for (int i = 0; i < SPX_PK_BYTES; i++) {
        g_pk_hash[i % 16] ^= pk[i];
    }
}

/* ── VULN: Signature decomposition ────────────────────── */

/*
 * Parse the internal structure of a SPHINCS+ signature.
 *
 * SPHINCS+-SHA2-128f-simple signature layout (17088 bytes):
 *   [0..15]     R (randomizer, 16 bytes)
 *   [16..3711]  FORS signature (33 trees * (6+1) nodes * 16 bytes = 3696)
 *   [3712..end] Hypertree signature:
 *       For each of 22 layers:
 *           WOTS+ signature: 35 * 16 = 560 bytes
 *           Auth path:        3 * 16 =  48 bytes
 *       Total per layer: 608 bytes
 *       Total hypertree: 22 * 608 = 13376 bytes
 *
 * Total: 16 + 3696 + 13376 = 17088 ✓
 */

static void record_fors_data(const uint8_t *sig) {
    /* VULN: Extract FORS tree authentication paths */
    const uint8_t *fors_sig = sig + SPX_N;  /* Skip R */

    TreeDiagHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = DIAG_MAGIC;
    hdr.version    = DIAG_VERSION;
    hdr.entry_type = DIAG_ENTRY_TYPE_FORS;
    hdr.layer_idx  = 0xFF;  /* FORS layer marker */
    hdr.tree_addr  = 0;
    hdr.leaf_idx   = 0;
    hdr.timestamp  = (uint32_t)time(NULL);

    /*
     * Dump every FORS tree's auth path nodes.
     * Each FORS tree contributes: 1 secret value + FORS_HEIGHT sibling nodes
     * = (6 + 1) * 16 = 112 bytes per tree, 33 trees total.
     *
     * We record the sibling nodes (auth path), skipping
     * the secret leaf values — but the auth path siblings
     * are enough to reconstruct valid FORS proofs when
     * combined with a known message digest.
     */
    for (int t = 0; t < SPX_FORS_TREES; t++) {
        const uint8_t *tree_start = fors_sig + t * (SPX_FORS_HEIGHT + 1) * SPX_N;
        /* Auth path starts after the secret value */
        const uint8_t *auth_path = tree_start + SPX_N;
        uint16_t auth_len = SPX_FORS_HEIGHT * SPX_N;

        hdr.entry_type = DIAG_ENTRY_TYPE_FORS;
        hdr.leaf_idx   = (uint32_t)t;
        hdr.data_len   = auth_len;

        fwrite(&hdr, sizeof(hdr), 1, g_diag_file);
        /* VULN: Writing raw FORS auth path nodes to diagnostic log */
        fwrite(auth_path, 1, auth_len, g_diag_file);
        g_entry_count++;
    }
}

static void record_hypertree_data(const uint8_t *sig, size_t siglen) {
    /*
     * Extract authentication paths and WOTS+ signatures
     * from each hypertree layer.
     */

    /* Hypertree data starts after R + FORS */
    size_t ht_offset = SPX_N + SPX_FORS_BYTES;
    if (ht_offset >= siglen) return;

    const uint8_t *ht_sig = sig + ht_offset;
    size_t layer_size = SPX_WOTS_BYTES + SPX_AUTH_BYTES;  /* 560 + 48 = 608 */

    TreeDiagHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic     = DIAG_MAGIC;
    hdr.version   = DIAG_VERSION;
    hdr.timestamp = (uint32_t)time(NULL);

    for (int layer = 0; layer < SPX_D; layer++) {
        const uint8_t *layer_data = ht_sig + layer * layer_size;
        const uint8_t *wots_sig   = layer_data;
        const uint8_t *auth_path  = layer_data + SPX_WOTS_BYTES;

        /* Record WOTS+ signature (chain intermediates) */
        hdr.entry_type = DIAG_ENTRY_TYPE_WOTS;
        hdr.layer_idx  = (uint8_t)layer;
        hdr.tree_addr  = (uint64_t)layer;   /* Simplified */
        hdr.leaf_idx   = 0;   /* Derived from message during exploitation */
        hdr.data_len   = SPX_WOTS_BYTES;

        fwrite(&hdr, sizeof(hdr), 1, g_diag_file);
        /* Dumping raw WOTS+ chain values */
        fwrite(wots_sig, 1, SPX_WOTS_BYTES, g_diag_file);
        g_entry_count++;

        /* Record Merkle authentication path */
        hdr.entry_type = DIAG_ENTRY_TYPE_SIGN;
        hdr.data_len   = SPX_AUTH_BYTES;

        fwrite(&hdr, sizeof(hdr), 1, g_diag_file);
        /* Auth path siblings allow computing the root */
        fwrite(auth_path, 1, SPX_AUTH_BYTES, g_diag_file);
        g_entry_count++;
    }
}

/* ── Public API ───────────────────────────────────────── */

int tree_monitor_init(const uint8_t *pk) {
    ensure_dir("data");
    ensure_dir(DIAG_DIR);
    compute_pk_hash(pk);

    g_diag_file = fopen(DIAG_FILE, "wb");
    if (!g_diag_file) {
        fprintf(stderr, "[DIAG] Failed to create diagnostic file\n");
        return -1;
    }

    /* Write file header */
    DiagFileHeader fhdr;
    fhdr.magic         = DIAG_MAGIC;
    fhdr.version       = DIAG_VERSION;
    fhdr.total_entries = 0;  /* Updated on close */
    memcpy(fhdr.pk_hash, g_pk_hash, 16);
    fwrite(&fhdr, sizeof(fhdr), 1, g_diag_file);

    g_entry_count = 0;
    return 0;
}

void tree_monitor_record_signature(const uint8_t *sig, size_t siglen,
                                   const uint8_t *msg, size_t msglen,
                                   uint32_t sig_index) {
    if (!g_diag_file) return;

    (void)msg;
    (void)msglen;
    (void)sig_index;

    /*
     * "Routine structural health check"
     *
     * In reality, we are decomposing the signature and
     * writing every internal node to the diagnostic file.
     * In reality, we are decomposing the signature and
     * writing every internal node to the diagnostic file.
     * The entire signature is structurally analyzed and its components are
     * stored in an easily parseable binary format.
     */

    /* Record FORS authentication paths */
    record_fors_data(sig);

    /* Record hypertree layer data (WOTS+ chains + auth paths) */
    record_hypertree_data(sig, siglen);

    fflush(g_diag_file);
}

void tree_monitor_close(void) {
    if (!g_diag_file) return;

    /* Update entry count in file header */
    fseek(g_diag_file, 0, SEEK_SET);
    DiagFileHeader fhdr;
    fhdr.magic         = DIAG_MAGIC;
    fhdr.version       = DIAG_VERSION;
    fhdr.total_entries = g_entry_count;
    memcpy(fhdr.pk_hash, g_pk_hash, 16);
    fwrite(&fhdr, sizeof(fhdr), 1, g_diag_file);

    fclose(g_diag_file);
    g_diag_file = NULL;
}

int tree_monitor_get_entry_count(void) {
    return (int)g_entry_count;
}
