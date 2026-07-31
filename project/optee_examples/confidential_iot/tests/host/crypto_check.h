#ifndef CIOT_CRYPTO_CHECK_H
#define CIOT_CRYPTO_CHECK_H

#include <stddef.h>
#include <stdint.h>

#include <confidential_iot_ta.h>

/*
 * The verifying half of the device-side test suite: everything the MANAGEMENT
 * SERVER does to a device's attestation evidence, reimplemented here so it can be
 * done in the guest, against real TA output, with no server and no network.
 *
 * These functions mirror CC_Server/server/attestation.py -
 * build_ta_identity_preimage() / compute_ta_identity_msg() and the ECDSA check in
 * verify_and_derive()'s step (e). Any divergence between this file, the TA, and
 * that Python is exactly the class of bug test 3 exists to catch, so keep all
 * three in step (see docs/TA_IDENTITY_IMPLEMENTATION.md §4).
 *
 * Everything returns 0 on success, non-zero otherwise. Nothing here holds a
 * secret: the tests only ever verify, and the "attacker" keys they generate are
 * throwaway.
 */

/* SHA-256 over one contiguous buffer. */
int cc_sha256(const uint8_t *in, size_t len, uint8_t out[32]);

/*
 * transcript_hash = SHA-256(nonce || server_ecdh_pub || device_ecdh_pub)
 *
 * The fTPM quote's qualifying data, and the first 32 bytes of CMD 3's evidence
 * block. Matches compute_transcript_hash() on the server.
 */
int cc_transcript_hash(const uint8_t *nonce, size_t nonce_len,
		       const uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
		       const uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
		       uint8_t out[32]);

/*
 * ta_identity_msg = SHA-256(TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL || nonce ||
 *                           server_ecdh_pub || device_ecdh_pub || device_id)
 *
 * The label is hashed WITHOUT its NUL terminator, and device_id goes last because
 * it is the only variable-length field. `device_id` is a NUL-terminated C string
 * here; the NUL is not hashed.
 *
 * Every parameter is one the tests substitute in an attack case - swap device_pub
 * for an attacker's key, or device_id for another device's, and the signature the
 * TA produced must stop verifying.
 */
int cc_ta_identity_digest(const uint8_t *nonce, size_t nonce_len,
			  const uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			  const uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			  const char *device_id, uint8_t out[32]);

/*
 * Verify a raw r||s ECDSA-P256 signature over an already-computed 32-byte digest,
 * under a 65-byte uncompressed SEC1 public key (0x04 || X || Y).
 *
 * Verifying over the DIGEST, not over the pre-image, is deliberate and is the trap
 * §6.1 of docs/TA_IDENTITY_IMPLEMENTATION.md records: the TA signs via
 * TEE_AsymmetricSignDigest, so hashing again here would reject every honest
 * device. Hence the split between cc_ta_identity_digest() and this.
 *
 * Returns 0 if the signature is VALID, non-zero otherwise - so a non-zero return
 * is the expected outcome in every attack case.
 */
int cc_ecdsa_p256_verify(const uint8_t pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE],
			 const uint8_t digest[32],
			 const uint8_t sig[TA_CONFIDENTIAL_IOT_TA_SIG_SIZE]);

/*
 * Generate a throwaway P-256 keypair and export the public half as a 65-byte
 * uncompressed SEC1 point. The private half is discarded: the tests only ever
 * need a well-formed point that the TA did not produce - a stand-in for the
 * ephemeral key a root-compromised Host would generate for itself, and for the
 * server's own ephemeral key.
 */
int cc_gen_p256_pub(uint8_t out_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE]);

/* Random bytes from /dev/urandom - nonces, and signatures that must not verify. */
int cc_random(uint8_t *out, size_t len);

#endif /* CIOT_CRYPTO_CHECK_H */
