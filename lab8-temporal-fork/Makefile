CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude -I../../external/pqclean/common
LDFLAGS = -L../../external/pqclean/common -lpqclean
TARGET = lab8.exe
FUZZ_TARGET = fuzz_harness.exe

SRC = src/main.c src/verifier.c src/fault_sim.c src/dilithium_wrapper.c
OBJ = $(SRC:.c=.o)

FUZZ_SRC = fuzz/fuzz_harness.c src/verifier.c src/fault_sim.c src/dilithium_wrapper.c
FUZZ_OBJ = $(FUZZ_SRC:.c=.o)

all: $(TARGET) $(FUZZ_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(FUZZ_TARGET): $(FUZZ_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del /Q /S *.o *.exe
