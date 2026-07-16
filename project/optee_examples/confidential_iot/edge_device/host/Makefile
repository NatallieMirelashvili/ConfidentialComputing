CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = main.o edge_device.o net.o \
       ../../sensor_module/sensor_module.o \
       ../../sensor_module/secure_element.o ../../attestation/attestation.o

CFLAGS += -Wall -I. -I../../sensor_module -I../../attestation -I../ta/include

# base64/SHA-256 come from mbedTLS (libmbedcrypto), JSON from cJSON. In the
# real image build these are provided by the Buildroot packages enabled via
# project/buildroot/packages.conf (headers/libs land in the target sysroot,
# which the cross toolchain searches by default); set SYSROOT explicitly if
# yours does not. Native builds need libmbedtls-dev + libcjson-dev installed.
ifneq ($(SYSROOT),)
CFLAGS += -I$(SYSROOT)/usr/include
LDFLAGS += -L$(SYSROOT)/usr/lib
endif
LDADD += -lmbedcrypto -lcjson

ifeq ($(TEEC_EXPORT),)
CFLAGS += -DCONFIDENTIAL_IOT_NATIVE
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
