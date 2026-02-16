CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude \
          -I../../external/pqclean/crypto_sign/sphincs-sha2-128f-simple/clean \
          -I../../external/pqclean/common

# Lab source files
LAB_SRC = src/main.c src/sphincs_wrapper.c src/tree_monitor.c \
          src/key_store.c src/service.c

# PQClean SPHINCS+ source files
SPX_DIR  = ../../external/pqclean/crypto_sign/sphincs-sha2-128f-simple/clean
SPX_SRC  = $(SPX_DIR)/address.c $(SPX_DIR)/merkle.c $(SPX_DIR)/wots.c \
           $(SPX_DIR)/wotsx1.c $(SPX_DIR)/utilsx1.c $(SPX_DIR)/utils.c \
           $(SPX_DIR)/fors.c $(SPX_DIR)/sign.c $(SPX_DIR)/hash_sha2.c \
           $(SPX_DIR)/thash_sha2_simple.c $(SPX_DIR)/context_sha2.c

# PQClean common
COMMON_DIR = ../../external/pqclean/common
COMMON_SRC = $(COMMON_DIR)/sha2.c $(COMMON_DIR)/randombytes.c

TARGET  = lab10.exe

ALL_SRC = $(LAB_SRC) $(SPX_SRC) $(COMMON_SRC)
ALL_OBJ = $(ALL_SRC:.c=.o)

all: dirs $(TARGET)

$(TARGET): $(ALL_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

dirs:
	@if not exist data\keys mkdir data\keys
	@if not exist data\diagnostics mkdir data\diagnostics
	@if not exist data\signatures mkdir data\signatures

clean:
	del /Q /S *.o 2>NUL
	del /Q $(TARGET) 2>NUL

.PHONY: all clean dirs
