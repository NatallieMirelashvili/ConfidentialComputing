CFG_TEE_TA_LOG_LEVEL ?= 4

# UUID ...0003. Its own filename purely so the installed .ta can never collide
# with the genuine ...0001; the mimicry itself happens at runtime, in the guest.
BINARY = 7d9f6d20-5f11-4d0c-9a17-61c9c91c0003

# THE POINT OF THIS FIXTURE. scripts/build.sh exports TA_SIGN_KEY=keys/ciot_ta.pem
# and every other TA in the tree picks it up through link.mk's `?=`. This one does
# not: it is signed with an attacker-held key instead, so OP-TEE's core - whose
# baked-in verifier public key is the project key, and is measured into PCR0 -
# must refuse to load it. That refusal is what test 1 asserts.
#
# `override` rather than a plain assignment so this survives a command-line
# TA_SIGN_KEY= too, and it is set BEFORE the include so link.mk's `?=` defers.
# Scoped to this one Makefile, so it cannot affect the core build, the dev-kit
# key export, or any other TA (see keys/README.md on why a GLOBAL per-TA override
# would break the image build).
override TA_SIGN_KEY := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/attacker_ta.pem

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
