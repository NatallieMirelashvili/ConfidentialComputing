#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#define ATTESTATION_QUOTE_B64_MAX	2048
#define ATTESTATION_SIG_B64_MAX		1024
#define ATTESTATION_PCR_TEXT_MAX	4096

struct attestation_evidence {
	char quote_b64[ATTESTATION_QUOTE_B64_MAX];
	char signature_b64[ATTESTATION_SIG_B64_MAX];
	/*
	 * Raw text captured from `tpm2_pcrread`, JSON-escaped and sent
	 * as-is; the server parses it to independently recompute the PCR
	 * digest rather than trusting a pre-digested value from the device.
	 */
	char pcr_values_text[ATTESTATION_PCR_TEXT_MAX];
};

/*
 * Gets the fTPM (optee_ftpm, a separate TA from our own - see
 * project docs/plan for why) to quote `transcript_hash` (32-byte SHA-256 of
 * nonce || server_ecdh_pub || device_ecdh_pub) under the device's
 * provisioned Attestation Key, via the Normal World tpm2-tools stack
 * (/dev/tpmrm0). `ak_handle` is the persistent AK handle produced once by
 * the provisioning script (see scripts/provision-device.sh) - e.g. "0x8101000A".
 *
 * Returns 0 on success (out is filled in), -1 on failure.
 *
 * NOTE: the exact tpm2_quote/tpm2_pcrread CLI flags used here should be
 * double-checked against `tpm2_quote --help`/`tpm2_pcrread --help` on the
 * actual target image (tpm2-tools 5.7) during first real-hardware testing -
 * this couldn't be executed/verified from the planning environment.
 */
int create_attestation_report(const uint8_t transcript_hash[32],
			      const char *ak_handle,
			      struct attestation_evidence *out);

#endif /* ATTESTATION_H */
