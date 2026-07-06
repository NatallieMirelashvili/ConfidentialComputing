/* SPDX-License-Identifier: BSD-2-Clause */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "trusted_app.h"

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

TEE_Result ta_authenticate_sensor(uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	return TEE_SUCCESS;
}

TEE_Result ta_process_sensor_data(uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	return TEE_SUCCESS;
}

TEE_Result ta_protect_sensor_data(uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	return TEE_SUCCESS;
}

TEE_Result ta_generate_attestation_evidence(uint32_t __unused param_types,
					    TEE_Param __unused params[4])
{
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t __unused cmd_id,
				      uint32_t __unused param_types,
				      TEE_Param __unused params[4])
{
	return TEE_SUCCESS;
}
