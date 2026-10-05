CC ?= gcc
VERSION := 1.0.0
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -static
CPPFLAGS += -DHARPRUN_VERSION=\"$(VERSION)\" -Isrc
OBJS = build/harprun.o build/simple-orchestration.o build/hash.o build/exec_x86_64.o

all: harprun

harprun: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

build/%.o: src/%.c src/harprun.h src/hash.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

build/exec_x86_64.o: src/exec_x86_64.S
	@mkdir -p build
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf build harprun

.PHONY: all clean
