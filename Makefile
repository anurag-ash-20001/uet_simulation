# ──────────────────────────────────────────────────────────────────
# Makefile  –  UET / libfabric v2.0 Simulation
# Assumes rdma-core / libfabric is installed system-wide.
#
# Usage:
#   make          – build
#   make run      – build and run all 20 tests
#   make clean    – remove build artefacts
# ──────────────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -std=c11
LIBS    = -lfabric -lpthread -lm

# rdma-core / libfabric include path (adjust if installed elsewhere)
INC     = $(shell pkg-config --cflags-only-I libfabric 2>/dev/null || echo "-I/usr/include/rdma")
LDFLAGS = $(shell pkg-config --libs-only-L  libfabric 2>/dev/null || echo "-L/usr/lib")

SRCS    = uet_sim_main.c uet_sim_core.c uet_sim_xfer.c
OBJS    = $(SRCS:.c=.o)
TARGET  = uet_sim

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo ""
	@echo "  Build OK → ./$(TARGET)"

%.o: %.c uet_sim.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

run: $(TARGET)
	@echo ""
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
