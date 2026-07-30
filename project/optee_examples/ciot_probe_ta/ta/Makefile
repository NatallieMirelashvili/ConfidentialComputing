CFG_TEE_TA_LOG_LEVEL ?= 4

# UUID ...0004. Signed with whatever TA_SIGN_KEY the build exports - i.e. the
# project key, same as the real TA - so this one LOADS. Its rogue sibling
# (../../ciot_rogue_ta) overrides TA_SIGN_KEY and must not.
#
# NOT ...0002: that belongs to the sensor_link PTA, which would silently shadow
# this TA. See the UUID allocation table in include/ciot_probe_ta.h.
BINARY = 7d9f6d20-5f11-4d0c-9a17-61c9c91c0004

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
