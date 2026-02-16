#ifndef LAB10_H
#define LAB10_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

/* ── SPHINCS+-SHA2-128f-simple parameters (from PQClean) ─── */
#define SPX_SK_BYTES    64
#define SPX_PK_BYTES    32
#define SPX_SIG_BYTES   17088
#define SPX_SEED_BYTES  48
#define SPX_N           16

/* Hypertree structure */
#define SPX_FULL_HEIGHT   66
#define SPX_D             22
#define SPX_TREE_HEIGHT   3     /* SPX_FULL_HEIGHT / SPX_D */
#define SPX_FORS_HEIGHT   6
#define SPX_FORS_TREES    33

/* WOTS+ */
#define SPX_WOTS_W      16
#define SPX_WOTS_LOGW   4
#define SPX_WOTS_LEN1   32    /* 8 * SPX_N / SPX_WOTS_LOGW */
#define SPX_WOTS_LEN2   3
#define SPX_WOTS_LEN    35    /* LEN1 + LEN2 */
#define SPX_WOTS_BYTES  560   /* SPX_WOTS_LEN * SPX_N */

/* Derived sizes */
#define SPX_FORS_BYTES  3696  /* (FORS_HEIGHT + 1) * FORS_TREES * N */
#define SPX_AUTH_BYTES  48    /* SPX_TREE_HEIGHT * SPX_N per layer */

/* ── Service configuration ──────────────────────────────── */
#define SERVICE_NAME        "QuantumRoot Signing Authority"
#define SERVICE_VERSION     "2.4.1"
#define KEY_DIR             "data/keys"
#define DIAG_DIR            "data/diagnostics"
#define DIAG_FILE           "data/diagnostics/tree_health.bin"
#define SIG_DIR             "data/signatures"
#define MAX_MSG_SIZE        4096
#define TREE_CACHE_ENTRIES  256

/* ── Diagnostic entry magic and format ──────────────────── */
#define DIAG_MAGIC          0x54524545  /* "TREE" */
#define DIAG_VERSION        0x0002
#define DIAG_ENTRY_TYPE_SIGN    0x01
#define DIAG_ENTRY_TYPE_FORS    0x02
#define DIAG_ENTRY_TYPE_WOTS    0x03

/* ── Tree diagnostic entry ──────────────────────────────── */
#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint8_t  entry_type;
    uint8_t  layer_idx;
    uint64_t tree_addr;
    uint32_t leaf_idx;
    uint32_t timestamp;
    uint16_t data_len;
    /* Variable-length data follows:
     *   - For SIGN entries: full auth_path (SPX_TREE_HEIGHT * SPX_N bytes)
     *   - For WOTS entries: chain intermediates (SPX_WOTS_LEN * SPX_N bytes)
     *   - For FORS entries: FORS auth path nodes
     */
} TreeDiagHeader;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint32_t total_entries;
    uint8_t  pk_hash[16];
} DiagFileHeader;

#pragma pack(pop)

/* ── Function prototypes ────────────────────────────────── */

/* sphincs_wrapper.c — Clean PQClean wrapper */
int spx_keygen(uint8_t *pk, uint8_t *sk);
int spx_sign(uint8_t *sig, size_t *siglen,
             const uint8_t *msg, size_t msglen,
             const uint8_t *sk);
int spx_verify(const uint8_t *sig, size_t siglen,
               const uint8_t *msg, size_t msglen,
               const uint8_t *pk);

/* key_store.c — Key persistence */
int  key_store_save(const char *dir, const uint8_t *pk, const uint8_t *sk);
int  key_store_load(const char *dir, uint8_t *pk, uint8_t *sk);
bool key_store_exists(const char *dir);

/* tree_monitor.c — VULNERABLE: diagnostic logging */
int  tree_monitor_init(const uint8_t *pk);
void tree_monitor_record_signature(const uint8_t *sig, size_t siglen,
                                   const uint8_t *msg, size_t msglen,
                                   uint32_t sig_index);
void tree_monitor_close(void);
int  tree_monitor_get_entry_count(void);

/* service.c — Signing service orchestrator */
int  service_init(void);
int  service_sign(const uint8_t *msg, size_t msglen, const char *out_path);
int  service_verify(const uint8_t *msg, size_t msglen, const char *sig_path);
int  service_batch_sign(int count);
void service_print_info(void);
void service_cleanup(void);

/* Utilities */
void hex_dump(const uint8_t *data, size_t len);
void print_banner(void);

#endif /* LAB10_H */
