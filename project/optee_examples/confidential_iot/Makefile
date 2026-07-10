export V ?= 0

HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) -C edge_device/host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C edge_device/ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) -C edge_device/host clean
	$(MAKE) -C edge_device/ta clean
