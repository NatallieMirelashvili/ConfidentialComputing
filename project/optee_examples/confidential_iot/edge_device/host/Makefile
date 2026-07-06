CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = main.o edge_device.o ../../sensor_module/sensor_module.o \
       ../../sensor_module/secure_element.o ../../attestation/attestation.o

CFLAGS += -Wall -I. -I../../sensor_module -I../../attestation -I../ta/include

ifeq ($(TEEC_EXPORT),)
CFLAGS += -DCONFIDENTIAL_IOT_NATIVE
LDADD +=
else
CFLAGS += -I$(TEEC_EXPORT)/include
LDADD += -lteec -L$(TEEC_EXPORT)/lib
endif

BINARY = optee_example_confidential_iot_edge

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
