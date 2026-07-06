CC ?= $(CROSS_COMPILE)gcc

OBJS = main.o server.o ../attestation/attestation.o
CFLAGS += -Wall -I. -I../attestation
BINARY = confidential_iot_server

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
