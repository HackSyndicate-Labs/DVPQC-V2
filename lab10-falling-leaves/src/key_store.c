/**
 * Key Store — SPHINCS+ Key Persistence
 * ======================================
 * Saves and loads SPHINCS+ key pairs to/from binary files.
 * This module contains NO vulnerabilities.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) mkdir(p)
#else
#define MKDIR(p) mkdir(p, 0755)
#endif
#include "lab10.h"

static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        MKDIR(path);
    }
}

int key_store_save(const char *dir, const uint8_t *pk, const uint8_t *sk) {
    ensure_dir("data");
    ensure_dir(dir);

    char path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/sphincs.pk", dir);
    f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(pk, 1, SPX_PK_BYTES, f);
    fclose(f);

    snprintf(path, sizeof(path), "%s/sphincs.sk", dir);
    f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(sk, 1, SPX_SK_BYTES, f);
    fclose(f);

    return 0;
}

int key_store_load(const char *dir, uint8_t *pk, uint8_t *sk) {
    char path[512];
    FILE *f;
    size_t n;

    snprintf(path, sizeof(path), "%s/sphincs.pk", dir);
    f = fopen(path, "rb");
    if (!f) return -1;
    n = fread(pk, 1, SPX_PK_BYTES, f);
    fclose(f);
    if (n != SPX_PK_BYTES) return -1;

    snprintf(path, sizeof(path), "%s/sphincs.sk", dir);
    f = fopen(path, "rb");
    if (!f) return -1;
    n = fread(sk, 1, SPX_SK_BYTES, f);
    fclose(f);
    if (n != SPX_SK_BYTES) return -1;

    return 0;
}

bool key_store_exists(const char *dir) {
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/sphincs.sk", dir);
    return stat(path, &st) == 0;
}
