/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TRUSTED_APP_H
#define TRUSTED_APP_H

#include <tee_internal_api.h>

TEE_Result ta_authenticate_sensor(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_process_sensor_data(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_protect_sensor_data(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_generate_attestation_evidence(uint32_t param_types,
					    TEE_Param params[4]);

#endif /* TRUSTED_APP_H */
