#include "crypto_check.h"

#include <stdio.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>

/*
 * RNG source. /dev/urandom rather than mbedTLS's entropy+CTR_DRBG stack: it is
 * three lines instead of a seeded context, and it keeps this file's dependency on
 * libmbedcrypto down to the ECP/ECDSA/SHA-256 modules the image is already known
 * to build (MBEDTLS_ECDSA_C + MBEDTLS_ECP_DP_SECP256R1_ENABLED). Nothing here
 * generates a long-lived secret, so the DRBG buys nothing.
 */
int cc_random(uint8_t *out, size_t len)
{
	FILE *f = fopen("/dev/urandom", "rb");
	size_t got;

	if (!f)
		return -1;

	got = fread(out, 1, len, f);
	fclose(f);
	return (got == len) ? 0 : -1;
}

/* mbedTLS's f_rng callback shape, backed by cc_random(). */
static int urandom_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return cc_random(out, len) == 0 ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

int cc_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
	return mbedtls_sha256(in, len, out, 0) == 0 ? 0 : -1;
}

int cc_transcript_hash(const uint8_t *nonce, size_t nonce_len,
		       const uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
		       const uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
		       uint8_t out[32])
{
	mbedtls_sha256_context ctx;
	int rc = -1;

	mbedtls_sha256_init(&ctx);
	if (mbedtls_sha256_starts(&ctx, 0) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, nonce, nonce_len) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, server_pub,
				  TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, device_pub,
				  TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	if (mbedtls_sha256_finish(&ctx, out) != 0)
		goto out;
	rc = 0;
out:
	mbedtls_sha256_free(&ctx);
	return rc;
}

int cc_ta_identity_digest(const uint8_t *nonce, size_t nonce_len,
			  const uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			  const uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			  const char *device_id, uint8_t out[32])
{
	static const char label[] = TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL;
	mbedtls_sha256_context ctx;
	int rc = -1;

	mbedtls_sha256_init(&ctx);
	if (mbedtls_sha256_starts(&ctx, 0) != 0)
		goto out;
	/* sizeof - 1: the label is hashed without its NUL, exactly as
	 * sign_ta_identity() does in the TA and TA_IDENTITY_LABEL does on the
	 * server. A one-byte disagreement here rejects every honest device. */
	if (mbedtls_sha256_update(&ctx, (const unsigned char *)label,
				  sizeof(label) - 1) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, nonce, nonce_len) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, server_pub,
				  TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, device_pub,
				  TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	if (mbedtls_sha256_update(&ctx, (const unsigned char *)device_id,
				  strlen(device_id)) != 0)
		goto out;
	if (mbedtls_sha256_finish(&ctx, out) != 0)
		goto out;
	rc = 0;
out:
	mbedtls_sha256_free(&ctx);
	return rc;
}

int cc_ecdsa_p256_verify(const uint8_t pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			 const uint8_t digest[32],
			 const uint8_t sig[TA_CONFIDENTIAL_IOT_TA_SIG_SIZE])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	mbedtls_mpi r;
	mbedtls_mpi s;
	int rc = -1;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
		goto out;
	/* Rejects a point that is not on the curve, so a malformed 65-byte blob
	 * fails here rather than silently verifying nothing. */
	if (mbedtls_ecp_point_read_binary(&grp, &q, pub,
					  TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	/* raw r||s, 32 bytes each - what TEE_AsymmetricSignDigest emits, and what
	 * the server feeds to encode_dss_signature(). */
	if (mbedtls_mpi_read_binary(&r, sig, 32) != 0)
		goto out;
	if (mbedtls_mpi_read_binary(&s, sig + 32, 32) != 0)
		goto out;

	if (mbedtls_ecdsa_verify(&grp, digest, 32, &q, &r, &s) != 0)
		goto out;
	rc = 0;
out:
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int cc_gen_p256_pub(uint8_t out_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	mbedtls_mpi d;
	size_t olen = 0;
	int rc = -1;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	mbedtls_mpi_init(&d);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
		goto out;
	if (mbedtls_ecp_gen_keypair(&grp, &d, &q, urandom_rng, NULL) != 0)
		goto out;
	if (mbedtls_ecp_point_write_binary(&grp, &q,
					   MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
					   out_pub,
					   TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
		goto out;
	if (olen != TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE)
		goto out;
	rc = 0;
out:
	/* The private half is thrown away here on purpose - see the header. */
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	return rc;
}
