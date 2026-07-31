/*
 * Rogue TA - a test fixture that is NEVER SUPPOSED TO RUN.
 *
 * It exists only as a signed artifact: a .ta file that an attacker with root in
 * Normal World could have produced, having tampered with a TA and re-signed it
 * with a key of their own. OP-TEE's core must refuse to load it, because the
 * public key baked into the core (and measured into PCR0) is the project key
 * from keys/ciot_ta.pem, not ../ta/attacker_ta.pem.
 *
 * Test 1 of optee_example_confidential_iot_tests uses it two ways: opened under
 * its own UUID, and copied over /lib/optee_armtz/<genuine-uuid>.ta to mimic the
 * real TA. Both must fail at signature verification.
 *
 * The entry points below are deliberately inert. If any of this code ever
 * executes, the test it belongs to has already failed.
 */
#include <tee_internal_api.h>

#include <ciot_rogue_ta.h>

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

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t __unused cmd_id,
				      uint32_t __unused param_types,
				      TEE_Param __unused params[4])
{
	return TEE_ERROR_NOT_SUPPORTED;
}
