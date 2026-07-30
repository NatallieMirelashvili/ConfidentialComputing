#ifndef CIOT_PROBE_TA_H
#define CIOT_PROBE_TA_H

/*
 * Storage-scope prober: a TEST FIXTURE, not part of the product.
 *
 * It exists to make one claim of docs/TA_IDENTITY_IMPLEMENTATION.md executable -
 * "OP-TEE secure storage is scoped to the TA UUID", which is the entire reason
 * Part A (the private TA signing key) gates Part B (the sealed TA identity key).
 * If another TA could read ciot.ta.identity, the signing key would not matter.
 *
 * This TA is signed with the PROJECT key, exactly like the real one, so it loads
 * normally. The only thing distinguishing it from the confidential_iot TA is its
 * UUID - which is precisely the variable under test. Its rogue sibling
 * (ciot_rogue_ta, UUID ...0003) is the same idea with the signing key as the
 * variable instead.
 *
 * Driven by optee_example_confidential_iot_tests (test 2).
 */
/*
 * UUID allocation in this project's 7d9f6d20-5f11-4d0c-9a17-61c9c91c00xx range.
 * CHECK THIS TABLE BEFORE ADDING ONE - and check project/optee_os_ext/ too, not
 * just the TAs here:
 *
 *   ...0001  confidential_iot TA   edge_device/ta/include/confidential_iot_ta.h
 *   ...0002  sensor_link PTA       optee_os_ext/lib/libutee/include/pta_sensor_link.h
 *   ...0003  ciot_rogue_ta         (test fixture, must not load)
 *   ...0004  this prober           (test fixture)
 *
 * ...0002 was this fixture's first choice and it silently did not work: OP-TEE
 * resolves pseudo-TAs BEFORE user TAs (tee_ta_manager.c calls
 * tee_ta_init_pseudo_ta_session() first), so the PTA shadowed this .ta entirely
 * and the session open was refused by the PTA's caller check - ACCESS_DENIED with
 * origin TRUSTED_APP, from a TA file that was built, installed and correctly
 * signed but never consulted.
 */
#define TA_CIOT_PROBE_UUID \
	{ 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x04 } }

/*
 * Attempt to open - and, if that succeeds, READ - a persistent object in
 * TEE_STORAGE_PRIVATE by name. The object ids of interest belong to the
 * confidential_iot TA ("ciot.ta.identity", "ciot.sensor.psk",
 * "ciot.server.pubkey"); every one of them must be invisible from here.
 *
 * The probe result travels in an output value rather than the command's return
 * code, so the caller can tell "the probe ran and storage said ITEM_NOT_FOUND"
 * apart from "the command itself was malformed".
 *
 * in:  params[0].memref = object id bytes (no NUL), 1..TA_CIOT_PROBE_OBJID_MAX.
 * out: params[1].value.a = TEE_Result of TEE_OpenPersistentObject.
 *      params[1].value.b = bytes successfully read out of it (0 unless the open
 *                          succeeded, i.e. unless the isolation has failed).
 *
 * Result: TEE_SUCCESS whenever the probe was performed, TEE_ERROR_BAD_PARAMETERS
 * on a malformed call.
 */
#define TA_CIOT_PROBE_CMD_OPEN_FOREIGN_OBJECT	0

/*
 * Control for the command above: create an object of OUR OWN under the given id,
 * read it back, verify the contents, then delete it. It proves this TA's storage
 * works at all - so the probe's ITEM_NOT_FOUND really is UUID scoping rather than
 * a broken fixture.
 *
 * Call it with PROBE_CONTROL_OBJID, never with an id the probe looks for: see the
 * comment on that macro in probe_ta.c for what sharing the name cost.
 *
 * in:  params[0].memref = object id bytes, as above.
 * out: params[1].value.a = TEE_SUCCESS if the whole create/read/verify/delete
 *                          round trip worked, else the first error hit.
 *
 * Result: TEE_SUCCESS whenever the round trip was attempted.
 */
#define TA_CIOT_PROBE_CMD_SELF_ROUNDTRIP	1

#define TA_CIOT_PROBE_OBJID_MAX		64

/*
 * Object id the self round-trip control must use. DELIBERATELY NOT one of the ids
 * the probe looks for.
 *
 * An earlier version used "ciot.ta.identity" for both. The control's delete was
 * missing TEE_DATA_FLAG_ACCESS_WRITE_META, so it panicked instead of deleting,
 * and the object stayed - under a name the probe treats as foreign. The next run
 * opened it, read 19 bytes of the prober's own marker back, and reported that
 * secure-storage isolation had failed. It had not. A control must never be able
 * to manufacture the evidence its own test looks for.
 */
#define PROBE_CONTROL_OBJID		"ciot.probe.control"

#endif /* CIOT_PROBE_TA_H */
