# Lab 11 Rootless Makefile

CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O2 -Iinclude -Isrc/pqclean -Isrc/pqclean/common
CXXFLAGS = -Wall -Wextra -O2 -std=c++11 -Iinclude -Isrc/pqclean -Isrc/pqclean/common

# Source files
C_SRCS = src/pqclean/address.c \
         src/pqclean/context_sha2.c \
         src/pqclean/fors.c \
         src/pqclean/hash_sha2.c \
         src/pqclean/merkle.c \
         src/pqclean/sign.c \
         src/pqclean/thash_sha2_simple.c \
         src/pqclean/utils.c \
         src/pqclean/utilsx1.c \
         src/pqclean/wots.c \
         src/pqclean/wotsx1.c \
         src/pqclean/common/sha2.c \
         src/pqclean/common/randombytes.c

CPP_SRCS = src/main.cpp \
           src/oqs_cpp.cpp

# Object files
C_OBJS = $(C_SRCS:.c=.o)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)

# Target
TARGET = lab11.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(C_OBJS) $(CPP_OBJS)
	$(CXX) -o $@ $^

collider: $(C_OBJS) solution/collider.o src/oqs_cpp.o
	$(CXX) -o solution/collider.exe $^

solution/collider.o: solution/collider.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(C_OBJS) $(CPP_OBJS) $(TARGET) spincs.pk sphincs.sk sig.bin
