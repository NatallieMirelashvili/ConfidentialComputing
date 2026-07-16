#include "attestation.h"

#include <mbedtls/base64.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_whole_file(const char *path, uint8_t *buf, size_t cap,
			   size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return -1;

	n = fread(buf, 1, cap, f);
	if (ferror(f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*out_len = n;
	return 0;
}

static int read_text_file(const char *path, char *buf, size_t cap)
{
	size_t n;

	if (cap == 0 || read_whole_file(path, (uint8_t *)buf, cap - 1, &n) != 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

int create_attestation_report(const uint8_t transcript_hash[32],
			      const char *ak_handle,
			      struct attestation_evidence *out)
{
	char hash_hex[65];
	char msg_path[] = "/tmp/ciot_quote_msg_XXXXXX";
	char sig_path[] = "/tmp/ciot_quote_sig_XXXXXX";
	char pcr_path[] = "/tmp/ciot_pcr_out_XXXXXX";
	char cmd[512];
	uint8_t raw_msg[1024];
	uint8_t raw_sig[512];
	size_t raw_msg_len = 0;
	size_t raw_sig_len = 0;
	size_t olen;
	size_t i;
	int fd;
	int ret = -1;

	for (i = 0; i < 32; i++)
		snprintf(hash_hex + i * 2, 3, "%02x", transcript_hash[i]);

	fd = mkstemp(msg_path);
	if (fd < 0)
		return -1;
	close(fd);

	fd = mkstemp(sig_path);
	if (fd < 0) {
		unlink(msg_path);
		return -1;
	}
	close(fd);

	fd = mkstemp(pcr_path);
	if (fd < 0) {
		unlink(msg_path);
		unlink(sig_path);
		return -1;
	}
	close(fd);

	/*
	 * -q takes the qualifying data (our transcript hash) as a hex string;
	 * -m/-s dump the signed attestation structure and its signature to
	 * files (binary TPMS_ATTEST / TPMT_SIGNATURE, base64-encoded below
	 * for JSON transport - the server parses these structures directly,
	 * it never needs the CLI's own text summary).
	 * See the NOTE in attestation.h re: verifying these flags against
	 * the installed tpm2-tools 5.7 on first real-hardware test.
	 */
	snprintf(cmd, sizeof(cmd),
		 "tpm2_quote -c %s -l sha256:0 -q %s -m %s -s %s -g sha256 "
		 ">/dev/null 2>&1",
		 ak_handle, hash_hex, msg_path, sig_path);
	if (system(cmd) != 0)
		goto out;

	snprintf(cmd, sizeof(cmd), "tpm2_pcrread sha256:0 > %s 2>&1", pcr_path);
	if (system(cmd) != 0)
		goto out;

	/*
	 * tpm2_quote -m (tpm2-tools 5.x, verified on the target image) writes
	 * the raw TPMS_ATTEST body with no size prefix, but the server parses
	 * a TPM2B_ATTEST - so prepend the 2-byte big-endian size the TPM2B
	 * wrapper would carry. The signature covers only the body, so this
	 * changes nothing cryptographically.
	 */
	if (read_whole_file(msg_path, raw_msg + 2, sizeof(raw_msg) - 2,
			    &raw_msg_len) != 0)
		goto out;
	raw_msg[0] = (uint8_t)(raw_msg_len >> 8);
	raw_msg[1] = (uint8_t)(raw_msg_len & 0xff);
	raw_msg_len += 2;
	if (read_whole_file(sig_path, raw_sig, sizeof(raw_sig), &raw_sig_len) != 0)
		goto out;
	if (read_text_file(pcr_path, out->pcr_values_text,
			    sizeof(out->pcr_values_text)) != 0)
		goto out;

	if (mbedtls_base64_encode((unsigned char *)out->quote_b64,
				   sizeof(out->quote_b64), &olen,
				   raw_msg, raw_msg_len) != 0)
		goto out;
	if (mbedtls_base64_encode((unsigned char *)out->signature_b64,
				   sizeof(out->signature_b64), &olen,
				   raw_sig, raw_sig_len) != 0)
		goto out;

	ret = 0;

out:
	unlink(msg_path);
	unlink(sig_path);
	unlink(pcr_path);
	return ret;
}
