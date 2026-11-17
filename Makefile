# BruteForce Attack Detector Makefile
# Academic Data Structures and Algorithms (DSA) Project
# C11 Core Backend

CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2 -Isrc

SRC = src/main.c src/database.c src/stack.c src/queue.c src/detector.c
OBJ = $(SRC:.c=.o)

ifeq ($(OS),Windows_NT)
    TARGET = bruteforce_detector.exe
    RM = del /Q /F
else
    TARGET = bruteforce_detector
    RM = rm -f
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

test: $(TARGET)
	./$(TARGET) test

run: $(TARGET)
	python gui/app.py

clean:
ifeq ($(OS),Windows_NT)
	-del /Q /F bruteforce_detector.exe src\bruteforce_detector.exe database\.runtime_state.dat 2>nul
else
	$(RM) $(TARGET) src/$(TARGET) database/.runtime_state.dat
endif

.PHONY: all test run clean
