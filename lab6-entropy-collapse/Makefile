# Lab 6: Entropy Collapse - Hardcore Edition
# Makefile

CC = gcc
CXX = g++
CFLAGS = -O3 -Wall -Wextra -Wno-unused-parameter -I../../external/pqclean/common -I../../external/pqclean/crypto_kem/ml-kem-768/clean -Iinclude
CXXFLAGS = -O3 -Wall -Wextra -std=c++17 -I../../external/pqclean/common -I../../external/pqclean/crypto_kem/ml-kem-768/clean -Iinclude

# Paths
PQCLEAN_COMMON = ../external/pqclean/common
PQCLEAN_KEM = ../external/pqclean/crypto_kem/ml-kem-768/clean

# Sources
COMMON_SRCS = $(PQCLEAN_COMMON)/fips202.c $(PQCLEAN_COMMON)/sha2.c $(PQCLEAN_COMMON)/sp800-185.c $(PQCLEAN_COMMON)/nistseedexpander.c $(PQCLEAN_COMMON)/aes.c
KEM_SRCS = $(wildcard $(PQCLEAN_KEM)/*.c)
LAB_SRCS = src/main.cpp src/Utils/EntropyPool.cpp src/Crypto/KyberManager.cpp src/Radio/Transceiver.cpp

# Objects
COMMON_OBJS = $(COMMON_SRCS:.c=.o)
KEM_OBJS = $(KEM_SRCS:.c=.o)
LAB_OBJS = $(LAB_SRCS:.cpp=.o)

# Target
TARGET = lab6_entropy_collapse

all: $(TARGET)

$(TARGET): $(COMMON_OBJS) $(KEM_OBJS) $(LAB_OBJS)
	$(CXX) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(COMMON_OBJS) $(KEM_OBJS) $(LAB_OBJS) $(TARGET)
