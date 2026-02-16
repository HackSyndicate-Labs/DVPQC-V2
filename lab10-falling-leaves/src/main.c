/**
 * QuantumRoot Signing Authority — CLI Entry Point
 * ==================================================
 * SPHINCS+-SHA2-128f-simple digital signature service
 * with integrated tree health monitoring.
 *
 * usage:
 *   lab10 --keygen              Generate a new keypair
 *   lab10 --sign <message>      Sign a message
 *   lab10 --verify <msg> <sig>  Verify a signature file
 *   lab10 --batch <count>       Batch sign random documents
 *   lab10 --info                Print algorithm parameters
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lab10.h"

void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║     QuantumRoot Signing Authority v2.4.1      ║\n");
    printf("  ║     SPHINCS+-SHA2-128f-simple                 ║\n");
    printf("  ║     \"Every leaf tells a story\"                ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s --keygen               Generate SPHINCS+ keypair\n", prog);
    printf("  %s --sign <message>       Sign a message\n", prog);
    printf("  %s --verify <msg> <sig>   Verify signature file\n", prog);
    printf("  %s --batch <count>        Batch sign documents\n", prog);
    printf("  %s --info                 Print algorithm info\n", prog);
}

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    srand((unsigned)time(NULL));

    if (strcmp(argv[1], "--info") == 0) {
        service_print_info();
        return 0;
    }

    if (strcmp(argv[1], "--keygen") == 0) {
        printf("[KEYGEN] Initializing key generation...\n");
        if (service_init() != 0) return 1;
        service_cleanup();
        printf("[KEYGEN] Done. Keys stored in %s/\n", KEY_DIR);
        return 0;
    }

    if (strcmp(argv[1], "--sign") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: --sign requires a message argument\n");
            return 1;
        }
        if (service_init() != 0) return 1;

        const char *msg = argv[2];
        char sigpath[256];
        snprintf(sigpath, sizeof(sigpath), "%s/sig_manual.bin", SIG_DIR);

        printf("[SIGN] Message: \"%s\"\n", msg);
        printf("[SIGN] Generating SPHINCS+ signature...\n");

        if (service_sign((const uint8_t *)msg, strlen(msg), sigpath) == 0) {
            printf("[SIGN] Signature saved to %s\n", sigpath);
            printf("[SIGN] Signature size: %d bytes\n", SPX_SIG_BYTES);
        } else {
            fprintf(stderr, "[SIGN] Failed\n");
            service_cleanup();
            return 1;
        }

        service_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "--verify") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: --verify requires <message> <signature_file>\n");
            return 1;
        }
        if (service_init() != 0) return 1;

        const char *msg = argv[2];
        const char *sigfile = argv[3];

        printf("[VERIFY] Message: \"%s\"\n", msg);
        printf("[VERIFY] Signature: %s\n", sigfile);

        int result = service_verify((const uint8_t *)msg, strlen(msg), sigfile);

        if (result == 0) {
            printf("\n");
            printf("  ╔═══════════════════════════════════════╗\n");
            printf("  ║  [✓] SIGNATURE VALID                  ║\n");
            printf("  ║  Document authenticated successfully  ║\n");
            printf("  ╚═══════════════════════════════════════╝\n");
        } else {
            printf("\n");
            printf("  ╔═══════════════════════════════════════╗\n");
            printf("  ║  [✗] SIGNATURE INVALID                ║\n");
            printf("  ║  Verification failed                  ║\n");
            printf("  ╚═══════════════════════════════════════╝\n");
        }

        service_cleanup();
        return result;
    }

    if (strcmp(argv[1], "--batch") == 0) {
        int count = 20;  /* default */
        if (argc >= 3) count = atoi(argv[2]);
        if (count <= 0 || count > 1000) {
            fprintf(stderr, "Error: count must be 1-1000\n");
            return 1;
        }
        if (service_init() != 0) return 1;

        if (service_batch_sign(count) != 0) {
            service_cleanup();
            return 1;
        }

        service_cleanup();
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage(argv[0]);
    return 1;
}
