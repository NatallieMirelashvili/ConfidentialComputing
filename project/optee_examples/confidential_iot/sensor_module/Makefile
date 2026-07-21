# Builds sensor_daemon as a NATIVE binary for the physical/dev host machine
# running QEMU - it is not part of the guest image (see the top-level
# CMakeLists.txt's note) and must not be cross-compiled for the target.
CC      ?= cc
CFLAGS  += -Wall -I.
LDADD   += -lssl -lcrypto

BINARY = sensor_daemon
OBJS = sensor_daemon.o

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
