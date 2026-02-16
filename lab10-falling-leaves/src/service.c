/**
 * Signing Service Orchestrator
 * ==============================
 * Manages the lifecycle of the QuantumRoot Signing Authority.
 * Coordinates key generation, signing, verification, and
 * tree health monitoring.
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
static uint8_t g_pk[SPX_PK_BYTES];
static uint8_t g_sk[SPX_SK_BYTES];
static bool g_initialized = false;
static uint32_t g_sig_count = 0;

static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        MKDIR(path);
    }
}

/* ── Public API ───────────────────────────────────────── */

int service_init(void) {
    printf("[INIT] %s v%s\n", SERVICE_NAME, SERVICE_VERSION);

    if (key_store_exists(KEY_DIR)) {
        printf("[INIT] Loading existing keypair...\n");
        if (key_store_load(KEY_DIR, g_pk, g_sk) != 0) {
            fprintf(stderr, "[ERROR] Failed to load keypair\n");
            return -1;
        }
    } else {
        printf("[INIT] Generating SPHINCS+-SHA2-128f-simple keypair...\n");
        printf("[INIT] This may take a moment...\n");
        if (spx_keygen(g_pk, g_sk) != 0) {
            fprintf(stderr, "[ERROR] Key generation failed\n");
            return -1;
        }
        if (key_store_save(KEY_DIR, g_pk, g_sk) != 0) {
            fprintf(stderr, "[WARN] Failed to persist keypair\n");
        }
        printf("[INIT] Keypair generated and stored\n");
    }

    /* Initialize tree health monitor */
    if (tree_monitor_init(g_pk) != 0) {
        fprintf(stderr, "[WARN] Tree monitor initialization failed\n");
    }

    printf("[INIT] Public key: ");
    hex_dump(g_pk, SPX_PK_BYTES);
    printf("[INIT] System ready\n\n");

    g_initialized = true;
    g_sig_count = 0;
    return 0;
}

int service_sign(const uint8_t *msg, size_t msglen, const char *out_path) {
    if (!g_initialized) {
        fprintf(stderr, "[ERROR] Service not initialized\n");
        return -1;
    }

    uint8_t sig[SPX_SIG_BYTES];
    size_t siglen = 0;

    if (spx_sign(sig, &siglen, msg, msglen, g_sk) != 0) {
        fprintf(stderr, "[ERROR] Signing failed\n");
        return -1;
    }

    g_sig_count++;

    /* Write signature to file */
    if (out_path) {
        ensure_dir(SIG_DIR);
        FILE *f = fopen(out_path, "wb");
        if (f) {
            fwrite(sig, 1, siglen, f);
            fclose(f);
        }
    }

    /*
     * Run tree health diagnostics after each signing
     * to monitor structural integrity of the hypertree.
     */
    tree_monitor_record_signature(sig, siglen, msg, msglen, g_sig_count);

    return 0;
}

int service_verify(const uint8_t *msg, size_t msglen, const char *sig_path) {
    if (!g_initialized) {
        fprintf(stderr, "[ERROR] Service not initialized\n");
        return -1;
    }

    FILE *f = fopen(sig_path, "rb");
    if (!f) {
        fprintf(stderr, "[ERROR] Cannot open signature file: %s\n", sig_path);
        return -1;
    }

    uint8_t sig[SPX_SIG_BYTES];
    size_t siglen = fread(sig, 1, SPX_SIG_BYTES, f);
    fclose(f);

    if (siglen == 0) {
        fprintf(stderr, "[ERROR] Empty signature file\n");
        return -1;
    }

    int result = spx_verify(sig, siglen, msg, msglen, g_pk);
    return result;
}

int service_batch_sign(int count) {
    if (!g_initialized) {
        fprintf(stderr, "[ERROR] Service not initialized\n");
        return -1;
    }

    printf("[BATCH] Signing %d documents...\n", count);
    time_t t0 = time(NULL);

    for (int i = 0; i < count; i++) {
        /* Generate a pseudo-random document */
        char doc[256];
        snprintf(doc, sizeof(doc),
                 "QuantumRoot Certificate #%05d [ts=%lu nonce=%08x]",
                 i, (unsigned long)time(NULL), (unsigned)rand());

        char sigpath[256];
        snprintf(sigpath, sizeof(sigpath), "%s/sig_%05d.bin", SIG_DIR, i);

        if (service_sign((const uint8_t *)doc, strlen(doc), sigpath) != 0) {
            fprintf(stderr, "[BATCH] Failed at document %d\n", i);
            return -1;
        }

        if ((i + 1) % 10 == 0 || i == count - 1) {
            printf("  [%d/%d] signatures generated\n", i + 1, count);
        }
    }

    time_t elapsed = time(NULL) - t0;
    printf("[BATCH] Complete in %lds\n", (long)elapsed);
    printf("[BATCH] Tree diagnostics: %d entries recorded\n",
           tree_monitor_get_entry_count());
    return 0;
}

void service_print_info(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  %s          ║\n", SERVICE_NAME);
    printf("║  Version: %s                          ║\n", SERVICE_VERSION);
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  Algorithm : SPHINCS+-SHA2-128f-simple   ║\n");
    printf("║  SK size   : %d bytes                    ║\n", SPX_SK_BYTES);
    printf("║  PK size   : %d bytes                    ║\n", SPX_PK_BYTES);
    printf("║  Sig size  : %d bytes                ║\n", SPX_SIG_BYTES);
    printf("║  Security  : NIST Level 1               ║\n");
    printf("║  Hypertree : %d layers × %d levels        ║\n", SPX_D, SPX_TREE_HEIGHT);
    printf("║  FORS      : %d trees × height %d         ║\n", SPX_FORS_TREES, SPX_FORS_HEIGHT);
    printf("╚══════════════════════════════════════════╝\n");
}

void service_cleanup(void) {
    tree_monitor_close();
    g_initialized = false;
    printf("[EXIT] Tree diagnostics finalized\n");
    printf("[EXIT] %d signatures processed\n", g_sig_count);
}

void hex_dump(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
