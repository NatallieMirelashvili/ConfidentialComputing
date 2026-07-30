/*
 * Storage-scope prober TA - a test fixture. See ciot_probe_ta.h for what it is
 * for and why it is signed with the project key rather than an attacker one.
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <ciot_probe_ta.h>

/* Whatever we write in the self round-trip control. Arbitrary, just has to come
 * back byte-identical. It doubles as a signature: if a "foreign" object we manage
 * to open contains exactly these bytes, it is our own leftover, not a breach. */
static const uint8_t probe_marker[] = "ciot-probe-control";

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

/* Copy the caller's object id out of shared memory and length-check it. */
static TEE_Result copy_objid(TEE_Param params[4],
			     uint8_t id[TA_CIOT_PROBE_OBJID_MAX], size_t *id_len)
{
	if (params[0].memref.size == 0 ||
	    params[0].memref.size > TA_CIOT_PROBE_OBJID_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemMove(id, params[0].memref.buffer, params[0].memref.size);
	*id_len = params[0].memref.size;
	return TEE_SUCCESS;
}

/*
 * Try to open a persistent object belonging to another TA, and read it if the
 * open unexpectedly succeeds. Reading matters: an open alone could in principle
 * succeed on a metadata-only handle, whereas bytes coming back is unambiguous
 * evidence that another TA's sealed data was exposed.
 */
static TEE_Result probe_foreign_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint8_t id[TA_CIOT_PROBE_OBJID_MAX];
	uint8_t stolen[64];
	size_t id_len;
	size_t got = 0;
	TEE_Result res;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = copy_objid(params, id, &id_len);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, id_len,
				       TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (res == TEE_SUCCESS) {
		/* Isolation has failed - OR this is litter from an older build of
		 * this fixture (see PROBE_CONTROL_OBJID). Read it and find out;
		 * only the second can match probe_marker, since anything the
		 * confidential_iot TA seals is key material of a different length. */
		if (TEE_ReadObjectData(obj, stolen, sizeof(stolen), &got) !=
		    TEE_SUCCESS)
			got = 0;
		TEE_CloseObject(obj);

		if (got == sizeof(probe_marker) &&
		    TEE_MemCompare(stolen, probe_marker, got) == 0) {
			/*
			 * Ours. Delete it and probe again, so the answer this
			 * command returns is about isolation rather than about
			 * the fixture's own history. WRITE_META is required to
			 * delete: without it the delete syscall fails and
			 * TEE_CloseAndDeletePersistentObject1 PANICS rather than
			 * returning - which is how the litter got here.
			 */
			if (TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id,
						     id_len,
						     TEE_DATA_FLAG_ACCESS_READ |
						     TEE_DATA_FLAG_ACCESS_WRITE_META,
						     &obj) == TEE_SUCCESS)
				TEE_CloseAndDeletePersistentObject1(obj);

			got = 0;
			res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id,
						       id_len,
						       TEE_DATA_FLAG_ACCESS_READ,
						       &obj);
			if (res == TEE_SUCCESS)
				TEE_CloseObject(obj);
		}

		TEE_MemFill(stolen, 0, sizeof(stolen));
	}

	params[1].value.a = res;
	params[1].value.b = (uint32_t)got;
	return TEE_SUCCESS;
}

/*
 * Control: an object of OUR OWN, created / read back / compared / deleted. Proves
 * this TA's storage works at all, so the probe's ITEM_NOT_FOUND above is UUID
 * scoping rather than a dead fixture.
 *
 * Two flags here are load-bearing and were both learned the hard way:
 *   - TEE_DATA_FLAG_OVERWRITE, unlike every object in the real TA (which is
 *     deliberately first-write-wins), so repeated test runs are idempotent;
 *   - TEE_DATA_FLAG_ACCESS_WRITE_META, without which the delete below does not
 *     merely fail - TEE_CloseAndDeletePersistentObject1 PANICS on every error
 *     except STORAGE_NOT_AVAILABLE (lib/libutee/tee_api_objects.c), killing the
 *     TA with TEEC_ERROR_TARGET_DEAD and leaving the object behind. Same trap as
 *     TEE_AsymmetricSignDigest, see docs/TA_IDENTITY_IMPLEMENTATION.md §7.
 */
static TEE_Result self_roundtrip(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint8_t id[TA_CIOT_PROBE_OBJID_MAX];
	uint8_t readback[sizeof(probe_marker)];
	size_t id_len;
	size_t got = 0;
	TEE_Result res;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = copy_objid(params, id, &id_len);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, id_len,
					 TEE_DATA_FLAG_ACCESS_WRITE |
					 TEE_DATA_FLAG_ACCESS_READ |
					 TEE_DATA_FLAG_ACCESS_WRITE_META |
					 TEE_DATA_FLAG_OVERWRITE,
					 TEE_HANDLE_NULL, probe_marker,
					 sizeof(probe_marker), &obj);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);
	if (res == TEE_SUCCESS)
		res = TEE_ReadObjectData(obj, readback, sizeof(readback), &got);
	if (res == TEE_SUCCESS &&
	    (got != sizeof(probe_marker) ||
	     TEE_MemCompare(readback, probe_marker, sizeof(probe_marker)) != 0))
		res = TEE_ERROR_GENERIC;

	/* Closing with delete also cleans up after a mid-way failure, so the
	 * next run starts from the same state as this one did. */
	TEE_CloseAndDeletePersistentObject1(obj);

out:
	params[1].value.a = res;
	params[1].value.b = (uint32_t)got;
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_CIOT_PROBE_CMD_OPEN_FOREIGN_OBJECT:
		return probe_foreign_object(param_types, params);
	case TA_CIOT_PROBE_CMD_SELF_ROUNDTRIP:
		return self_roundtrip(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
