#include "edge_device.h"

#include <confidential_iot_ta.h>
#include <attestation.h>
#include <net.h>

#include <cjson/cJSON.h>
#include <mbedtls/base64.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CONFIDENTIAL_IOT_NATIVE
#include <tee_client_api.h>
#endif

#define CIOT_LINE_MAX		16384
#define CIOT_NONCE_MAX		64
#define CIOT_ECDH_PUB_SIZE	TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE
#define CIOT_TRANSCRIPT_HASH_SIZE TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE
#define CIOT_SERVER_SIG_SIZE	TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE
#define CIOT_TA_SIG_SIZE	TA_CONFIDENTIAL_IOT_TA_SIG_SIZE
/* CMD 3 returns transcript_hash(32) || ta_sig(64) in one buffer - the GP API
 * allows only four params and all four are in use. See confidential_iot_ta.h. */
#define CIOT_EVIDENCE_BLOCK_SIZE TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE

/* Local device configuration, set up once by scripts/provision-device.sh
 * and read from /etc/confidential_iot/device.conf (env vars override). */
static char g_device_id[64] = "iot-edge-01";
static char g_server_host[64] = "127.0.0.1";
static uint16_t g_server_port = 9000;
static char g_ak_handle[32] = "0x8101000A";
/* Management-server admin API port (POST /api/devices/register), distinct
 * from g_server_port (the device-facing attestation port). Same host. */
static uint16_t g_admin_port = 8000;

/* Attestation-session state, valid between edge_attest_to_server() and the
 * subsequent edge_handshake() / edge_send_sensor_data_to_server() calls. */
static struct net_conn g_conn = { .fd = -1 };
static int g_conn_open;
static uint8_t g_nonce[CIOT_NONCE_MAX];
static size_t g_nonce_len;
static uint8_t g_server_ecdh_pub[CIOT_ECDH_PUB_SIZE];
/* Server-identity material for the device->server authentication (TOFU): the
 * server's identity public key (from attest_challenge) and its per-session
 * signature (from attest_result). Cached here across edge_attest_to_server()
 * and edge_handshake(), which passes both to the TA to verify + pin. */
static uint8_t g_server_identity_pub[CIOT_ECDH_PUB_SIZE];
static uint8_t g_server_sig[CIOT_SERVER_SIG_SIZE];
static int g_attested;
/* Monotonic-clock deadline (seconds) after which the current session is
 * treated as expired and the device re-attests. Set from the server's
 * session_ttl in each attest_result. */
static long g_session_expiry;
/* Sequence number the TA authenticated for the most recent READ_AND_PROTECT
 * call, set by ta_read_and_protect_encode() and put on the wire by
 * edge_send_sensor_data_to_server() for the server's anti-replay check. */
static uint32_t g_last_seq;

#ifndef CONFIDENTIAL_IOT_NATIVE
static TEEC_Context g_teec_ctx;
static TEEC_Session g_teec_sess;
static int g_teec_open;
#endif

static void load_config(void)
{
	FILE *f;
	char line[256];
	const char *env;

	f = fopen("/etc/confidential_iot/device.conf", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			char *eq = strchr(line, '=');
			char *nl;

			if (!eq)
				continue;
			*eq = '\0';
			nl = strchr(eq + 1, '\n');
			if (nl)
				*nl = '\0';

			if (strcmp(line, "device_id") == 0)
				snprintf(g_device_id, sizeof(g_device_id), "%s", eq + 1);
			else if (strcmp(line, "server_host") == 0)
				snprintf(g_server_host, sizeof(g_server_host), "%s", eq + 1);
			else if (strcmp(line, "server_port") == 0)
				g_server_port = (uint16_t)atoi(eq + 1);
			else if (strcmp(line, "ak_handle") == 0)
				snprintf(g_ak_handle, sizeof(g_ak_handle), "%s", eq + 1);
			else if (strcmp(line, "admin_port") == 0)
				g_admin_port = (uint16_t)atoi(eq + 1);
		}
		fclose(f);
	}

	env = getenv("CIOT_DEVICE_ID");
	if (env)
		snprintf(g_device_id, sizeof(g_device_id), "%s", env);
	env = getenv("CIOT_SERVER_HOST");
	if (env)
		snprintf(g_server_host, sizeof(g_server_host), "%s", env);
	env = getenv("CIOT_SERVER_PORT");
	if (env)
		g_server_port = (uint16_t)atoi(env);
	env = getenv("CIOT_AK_HANDLE");
	if (env)
		snprintf(g_ak_handle, sizeof(g_ak_handle), "%s", env);
	env = getenv("CIOT_ADMIN_PORT");
	if (env)
		g_admin_port = (uint16_t)atoi(env);
}

int edge_device_init(void)
{
	load_config();

#ifndef CONFIDENTIAL_IOT_NATIVE
	{
		TEEC_UUID uuid = TA_CONFIDENTIAL_IOT_UUID;
		TEEC_Result res;
		uint32_t err_origin;

		res = TEEC_InitializeContext(NULL, &g_teec_ctx);
		if (res != TEEC_SUCCESS)
			return -1;

		res = TEEC_OpenSession(&g_teec_ctx, &g_teec_sess, &uuid,
					TEEC_LOGIN_PUBLIC, NULL, NULL,
					&err_origin);
		if (res != TEEC_SUCCESS) {
			TEEC_FinalizeContext(&g_teec_ctx);
			return -1;
		}
		g_teec_open = 1;
	}
#endif
	return 0;
}

void edge_device_shutdown(void)
{
	if (g_conn_open) {
		net_close(&g_conn);
		g_conn_open = 0;
	}

#ifndef CONFIDENTIAL_IOT_NATIVE
	if (g_teec_open) {
		TEEC_CloseSession(&g_teec_sess);
		TEEC_FinalizeContext(&g_teec_ctx);
		g_teec_open = 0;
	}
#endif
}

int edge_authenticate_sensor(void)
{
#ifndef CONFIDENTIAL_IOT_NATIVE
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	if (!g_teec_open)
		return -1;

	/* No parameters, by design: the whole HMAC-SHA256 challenge-response
	 * happens TA<->sensor_link PTA, entirely inside Secure World (see
	 * ta_authenticate_sensor in trusted_app.c) - the Host only triggers
	 * it and never sees the challenge or the response. */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					  TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&g_teec_sess,
				  TA_CONFIDENTIAL_IOT_CMD_AUTHENTICATE_SENSOR,
				  &op, &err_origin);
	return (res == TEEC_SUCCESS) ? 0 : -1;
#else
	return -1;
#endif
}

/* Serialize msg, send it as one newline-framed line, and free everything.
 * Takes ownership of msg (a NULL msg reports failure). */
static int send_json_line(cJSON *msg)
{
	char *text;
	int rc;

	if (!msg)
		return -1;

	text = cJSON_PrintUnformatted(msg);
	cJSON_Delete(msg);
	if (!text)
		return -1;

	rc = net_send_line(&g_conn, text);
	cJSON_free(text);
	return rc;
}

#ifndef CONFIDENTIAL_IOT_NATIVE

/*
 * Ask the TA for this session's ephemeral ECDH public key plus its evidence
 * block: the transcript hash the fTPM will quote, followed by the TA's own
 * identity signature over that same session (see
 * TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE in
 * confidential_iot_ta.h). The two share params[3] because the GP Internal Core
 * API caps a command at four parameters.
 */
static int ta_handshake_init(uint8_t out_pub[CIOT_ECDH_PUB_SIZE],
			     uint8_t out_evidence[CIOT_EVIDENCE_BLOCK_SIZE])
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	if (!g_teec_open)
		return -1;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = out_pub;
	op.params[0].tmpref.size = CIOT_ECDH_PUB_SIZE;
	op.params[1].tmpref.buffer = g_nonce;
	op.params[1].tmpref.size = g_nonce_len;
	op.params[2].tmpref.buffer = g_server_ecdh_pub;
	op.params[2].tmpref.size = CIOT_ECDH_PUB_SIZE;
	op.params[3].tmpref.buffer = out_evidence;
	op.params[3].tmpref.size = CIOT_EVIDENCE_BLOCK_SIZE;

	res = TEEC_InvokeCommand(&g_teec_sess,
				  TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE,
				  &op, &err_origin);
	if (res != TEEC_SUCCESS ||
	    op.params[0].tmpref.size != CIOT_ECDH_PUB_SIZE ||
	    op.params[3].tmpref.size != CIOT_EVIDENCE_BLOCK_SIZE)
		return -1;

	return 0;
}

/*
 * Trigger the TA's inverted READ_AND_PROTECT command: no plaintext input at
 * all (the reading is pulled from the sensor_link PTA entirely inside
 * Secure World - see ta_read_and_protect in trusted_app.c), only the
 * resulting {nonce, ciphertext-with-tag, seq} ever crosses back to the Host.
 */
static int ta_read_and_protect_encode(char *output, size_t output_size)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;
	uint8_t nonce[12];
	uint8_t ciphertext[512];
	uint8_t combined[sizeof(nonce) + sizeof(ciphertext)];
	size_t combined_len;
	size_t olen;

	if (!g_teec_open)
		return -1;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_VALUE_OUTPUT,
					  TEEC_NONE);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = sizeof(nonce);
	op.params[1].tmpref.buffer = ciphertext;
	op.params[1].tmpref.size = sizeof(ciphertext);

	res = TEEC_InvokeCommand(&g_teec_sess,
				  TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT,
				  &op, &err_origin);
	if (res != TEEC_SUCCESS || op.params[0].tmpref.size != sizeof(nonce))
		return -1;

	/* Remember the seq the TA authenticated so the "data" message can carry
	 * it for the server's inner-session anti-replay check. */
	g_last_seq = op.params[2].value.a;

	combined_len = op.params[0].tmpref.size + op.params[1].tmpref.size;
	if (combined_len > sizeof(combined))
		return -1;

	memcpy(combined, nonce, op.params[0].tmpref.size);
	memcpy(combined + op.params[0].tmpref.size, ciphertext,
	       op.params[1].tmpref.size);

	if (mbedtls_base64_encode((unsigned char *)output, output_size, &olen,
				   combined, combined_len) != 0)
		return -1;

	return 0;
}

/*
 * One-time provisioning trigger for the Sensor Module's pre-shared secret
 * (see scripts/pair-sensor.sh and ta_provision_sensor_secret in
 * trusted_app.c). The secret transits this Normal-World buffer once, at
 * pairing time - an accepted, documented trust assumption inherent to any
 * shared-secret provisioning step on this emulated platform, distinct from
 * the ongoing sensor-data path this project's hard requirement is about.
 */
int edge_provision_sensor_secret(const uint8_t secret[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE])
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	if (!g_teec_open)
		return -1;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					  TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)secret;
	op.params[0].tmpref.size = TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE;

	res = TEEC_InvokeCommand(&g_teec_sess,
				  TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET,
				  &op, &err_origin);
	return (res == TEEC_SUCCESS) ? 0 : -1;
}

/*
 * One-time provisioning of the TA's own identity keypair. The TA mints it
 * inside the TEE on first call and seals it - bound to g_device_id - returning
 * only the 65-byte public point; later calls just re-export the same point, so
 * this is safe to run on every boot. See
 * TA_CONFIDENTIAL_IOT_CMD_GENERATE_TA_IDENTITY in confidential_iot_ta.h.
 *
 * g_device_id is deliberately not a parameter: using the same global that
 * edge_attest_to_server() puts in attest_response guarantees the identity the
 * TA seals is byte-identical to the one the server looks the TA key up by.
 */
int edge_provision_ta_identity(uint8_t out_pub[CIOT_ECDH_PUB_SIZE])
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;
	size_t id_len = strlen(g_device_id);

	if (!g_teec_open)
		return -1;
	if (id_len == 0 || id_len > TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX)
		return -1;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = g_device_id;
	op.params[0].tmpref.size = id_len;
	op.params[1].tmpref.buffer = out_pub;
	op.params[1].tmpref.size = CIOT_ECDH_PUB_SIZE;

	res = TEEC_InvokeCommand(&g_teec_sess,
				  TA_CONFIDENTIAL_IOT_CMD_GENERATE_TA_IDENTITY,
				  &op, &err_origin);
	if (res != TEEC_SUCCESS ||
	    op.params[1].tmpref.size != CIOT_ECDH_PUB_SIZE)
		return -1;

	return 0;
}

#else /* CONFIDENTIAL_IOT_NATIVE: no TEE client library available to link */

static int ta_handshake_init(uint8_t out_pub[CIOT_ECDH_PUB_SIZE],
			     uint8_t out_evidence[CIOT_EVIDENCE_BLOCK_SIZE])
{
	(void)out_pub; (void)out_evidence;
	return -1;
}

static int ta_read_and_protect_encode(char *output, size_t output_size)
{
	(void)output; (void)output_size;
	return -1;
}

int edge_provision_sensor_secret(const uint8_t secret[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE])
{
	(void)secret;
	return -1;
}

int edge_provision_ta_identity(uint8_t out_pub[CIOT_ECDH_PUB_SIZE])
{
	(void)out_pub;
	return -1;
}

#endif

int edge_call_ta(char *output, size_t output_size)
{
	return ta_read_and_protect_encode(output, output_size);
}

/* Monotonic seconds, for session-expiry deadlines (immune to wall-clock jumps;
 * only elapsed time matters). Falls back to time() if CLOCK_MONOTONIC fails. */
static long mono_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		return (long)ts.tv_sec;
	return (long)time(NULL);
}

int edge_attest_to_server(void)
{
	char line[CIOT_LINE_MAX];
	char device_pub_b64[128];
	char ta_sig_b64[128];
	uint8_t device_pub[CIOT_ECDH_PUB_SIZE];
	/* transcript_hash(32) || ta_sig(64), returned as one block by CMD 3. */
	uint8_t evidence[CIOT_EVIDENCE_BLOCK_SIZE];
	struct attestation_evidence ev;
	cJSON *msg;
	const cJSON *item;
	int ok;
	size_t olen;

	g_attested = 0;

	/* Reuse the existing connection when re-attesting (device-driven
	 * re-attestation on expiry): the server's per-connection loop handles a
	 * repeat "hello" and derives a fresh session over the same socket. */
	if (!g_conn_open) {
		if (net_connect(g_server_host, g_server_port, &g_conn) != 0)
			return -1;
		g_conn_open = 1;
	}

	msg = cJSON_CreateObject();
	if (!msg ||
	    !cJSON_AddStringToObject(msg, "type", "hello") ||
	    !cJSON_AddStringToObject(msg, "device_id", g_device_id)) {
		cJSON_Delete(msg);
		return -1;
	}
	if (send_json_line(msg) != 0)
		return -1;

	if (net_recv_line(&g_conn, line, sizeof(line)) < 0)
		return -1;

	msg = cJSON_Parse(line);
	if (!msg)
		return -1;

	/* The server answers an unenrolled device_id with {"type":"error",...}
	 * instead of a challenge. Distinguish "not registered" (retryable via
	 * self-registration) from any other failure. */
	item = cJSON_GetObjectItemCaseSensitive(msg, "type");
	if (cJSON_IsString(item) && strcmp(item->valuestring, "error") == 0) {
		const cJSON *err = cJSON_GetObjectItemCaseSensitive(msg, "error");
		int not_registered = cJSON_IsString(err) &&
			strstr(err->valuestring, "not registered") != NULL;

		cJSON_Delete(msg);
		return not_registered ? -2 : -1;
	}

	item = cJSON_GetObjectItemCaseSensitive(msg, "nonce");
	if (!cJSON_IsString(item) ||
	    mbedtls_base64_decode(g_nonce, sizeof(g_nonce), &g_nonce_len,
				   (const unsigned char *)item->valuestring,
				   strlen(item->valuestring)) != 0) {
		cJSON_Delete(msg);
		return -1;
	}

	item = cJSON_GetObjectItemCaseSensitive(msg, "server_ecdh_pub");
	if (!cJSON_IsString(item) ||
	    mbedtls_base64_decode(g_server_ecdh_pub,
				   sizeof(g_server_ecdh_pub), &olen,
				   (const unsigned char *)item->valuestring,
				   strlen(item->valuestring)) != 0 ||
	    olen != CIOT_ECDH_PUB_SIZE) {
		cJSON_Delete(msg);
		return -1;
	}

	/* Server-identity public key: pinned by the TA on first use, then
	 * required to match on every later handshake (TOFU). Same 65-byte SEC1
	 * point encoding as the ECDH keys. */
	item = cJSON_GetObjectItemCaseSensitive(msg, "server_identity_pub");
	if (!cJSON_IsString(item) ||
	    mbedtls_base64_decode(g_server_identity_pub,
				   sizeof(g_server_identity_pub), &olen,
				   (const unsigned char *)item->valuestring,
				   strlen(item->valuestring)) != 0 ||
	    olen != CIOT_ECDH_PUB_SIZE) {
		cJSON_Delete(msg);
		return -1;
	}
	cJSON_Delete(msg);

	/* The TA generates the ephemeral keypair and hands back the pubkey
	 * together with SHA-256(nonce || server_pub || device_pub) and its own
	 * identity signature over this session. */
	if (ta_handshake_init(device_pub, evidence) != 0)
		return -1;

	/* The fTPM quotes only the transcript hash - the first 32 bytes. */
	if (create_attestation_report(evidence, g_ak_handle, &ev) != 0)
		return -1;

	if (mbedtls_base64_encode((unsigned char *)device_pub_b64,
				   sizeof(device_pub_b64), &olen,
				   device_pub, CIOT_ECDH_PUB_SIZE) != 0)
		return -1;

	/* The TA identity signature rides alongside the quote; the server
	 * verifies it against the ta_pub pinned at registration before deriving
	 * any session key. Root cannot forge it - the key never leaves the TEE. */
	if (mbedtls_base64_encode((unsigned char *)ta_sig_b64,
				   sizeof(ta_sig_b64), &olen,
				   evidence + CIOT_TRANSCRIPT_HASH_SIZE,
				   CIOT_TA_SIG_SIZE) != 0)
		return -1;

	msg = cJSON_CreateObject();
	if (!msg ||
	    !cJSON_AddStringToObject(msg, "type", "attest_response") ||
	    !cJSON_AddStringToObject(msg, "device_id", g_device_id) ||
	    !cJSON_AddStringToObject(msg, "device_ecdh_pub", device_pub_b64) ||
	    !cJSON_AddStringToObject(msg, "quote", ev.quote_b64) ||
	    !cJSON_AddStringToObject(msg, "signature", ev.signature_b64) ||
	    !cJSON_AddStringToObject(msg, "pcr_values", ev.pcr_values_text) ||
	    !cJSON_AddStringToObject(msg, "ta_sig", ta_sig_b64)) {
		cJSON_Delete(msg);
		return -1;
	}
	if (send_json_line(msg) != 0)
		return -1;

	if (net_recv_line(&g_conn, line, sizeof(line)) < 0)
		return -1;

	msg = cJSON_Parse(line);
	if (!msg)
		return -1;
	ok = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(msg, "ok"));
	item = cJSON_GetObjectItemCaseSensitive(msg, "session_ttl");
	/* Track when to re-attest. Fall back to a conservative TTL if the
	 * server omits it, so we never treat the session as valid forever. */
	g_session_expiry = mono_now() +
		(cJSON_IsNumber(item) && item->valueint > 0 ? item->valueint : 300);
	if (ok) {
		/* On success the server also proves its own identity with a
		 * signature over this session's transcript; edge_handshake()
		 * hands it to the TA, which verifies it against the pinned
		 * server key before deriving the session key. Missing or
		 * wrong-length => reject before we ever trust the session. */
		item = cJSON_GetObjectItemCaseSensitive(msg, "server_sig");
		if (!cJSON_IsString(item) ||
		    mbedtls_base64_decode(g_server_sig, sizeof(g_server_sig),
					   &olen,
					   (const unsigned char *)item->valuestring,
					   strlen(item->valuestring)) != 0 ||
		    olen != CIOT_SERVER_SIG_SIZE) {
			cJSON_Delete(msg);
			return -1;
		}
	}
	cJSON_Delete(msg);
	if (!ok)
		return -1;

	g_attested = 1;
	return 0;
}

#define CIOT_ENROLLMENT_PATH "/etc/confidential_iot/enrollment.json"
#define CIOT_REGISTER_RESP_PATH "/tmp/ciot_register_resp.json"

/* POST the enrollment record (written by provision-device.sh - device_id +
 * AK pubkey + PCR baseline) to the management server's admin API, so a
 * never-registered device enrolls itself with no human/register-device.sh
 * step. Shells out to curl via system() rather than linking an HTTP/TLS
 * library into the Host CA - BusyBox's wget has no HTTPS support in this
 * rootfs, and the server's TLS transport is pinned to TLS 1.3 only, so a
 * real TLS client is required (see project/buildroot/packages.conf). */
static int edge_register_with_server(void)
{
	char cmd[512];
	char resp[512] = { 0 };
	FILE *f;
	size_t len;
	cJSON *msg;

	snprintf(cmd, sizeof(cmd),
		 "curl -sk -X POST --data-binary @%s -o %s "
		 "https://%s:%u/api/devices/register",
		 CIOT_ENROLLMENT_PATH, CIOT_REGISTER_RESP_PATH, g_server_host,
		 g_admin_port);

	if (system(cmd) != 0) {
		fprintf(stderr, "edge_device: registration request failed (curl)\n");
		return -1;
	}

	f = fopen(CIOT_REGISTER_RESP_PATH, "r");
	if (!f) {
		fprintf(stderr, "edge_device: no registration response\n");
		return -1;
	}
	len = fread(resp, 1, sizeof(resp) - 1, f);
	fclose(f);
	resp[len] = '\0';

	msg = cJSON_Parse(resp);
	if (!msg) {
		fprintf(stderr, "edge_device: unparseable registration response\n");
		return -1;
	}

	if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(msg, "ok"))) {
		const cJSON *err = cJSON_GetObjectItemCaseSensitive(msg, "error");

		fprintf(stderr,
			"edge_device: registration rejected: %s (admin must resolve manually)\n",
			cJSON_IsString(err) ? err->valuestring : "unknown error");
		cJSON_Delete(msg);
		return -1;
	}

	printf(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(msg, "already_registered")) ?
	       "edge_device: already registered\n" :
	       "edge_device: registered with the management server\n");
	cJSON_Delete(msg);
	return 0;
}

int edge_ensure_session(void)
{
	int rc;

	/* Still-valid session: nothing to do (attestation happens only when
	 * needed, not on every push/collect). */
	if (g_attested && mono_now() < g_session_expiry)
		return 0;

	rc = edge_attest_to_server();
	if (rc == -2) {
		fprintf(stderr,
			"edge_device: not registered, attempting self-registration...\n");
		if (edge_register_with_server() != 0)
			return -1;
		/* Same connection, repeat "hello" - already how device-driven
		 * re-attestation works (see edge_attest_to_server()). */
		rc = edge_attest_to_server();
	}
	if (rc != 0)
		return -1;

	if (edge_handshake() != 0)
		return -1;
	return 0;
}

void edge_reset_connection(void)
{
	if (g_conn_open) {
		net_close(&g_conn);
		g_conn_open = 0;
	}
	g_attested = 0;
	g_session_expiry = 0;
}

int edge_handshake(void)
{
	if (!g_attested)
		return -1;

#ifndef CONFIDENTIAL_IOT_NATIVE
	{
		TEEC_Operation op;
		TEEC_Result res;
		uint32_t err_origin;

		if (!g_teec_open)
			return -1;

		memset(&op, 0, sizeof(op));
		/* params[2]/[3] carry the server-identity pubkey + signature so
		 * the TA can authenticate the server (verify + TOFU-pin) before
		 * it derives the session key. */
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_INPUT);
		op.params[0].tmpref.buffer = g_server_ecdh_pub;
		op.params[0].tmpref.size = CIOT_ECDH_PUB_SIZE;
		op.params[1].tmpref.buffer = g_nonce;
		op.params[1].tmpref.size = g_nonce_len;
		op.params[2].tmpref.buffer = g_server_identity_pub;
		op.params[2].tmpref.size = CIOT_ECDH_PUB_SIZE;
		op.params[3].tmpref.buffer = g_server_sig;
		op.params[3].tmpref.size = CIOT_SERVER_SIG_SIZE;

		res = TEEC_InvokeCommand(&g_teec_sess,
					  TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE,
					  &op, &err_origin);
		return (res == TEEC_SUCCESS) ? 0 : -1;
	}
#else
	return -1;
#endif
}

int edge_send_sensor_data_to_server(const char *protected_data,
				    size_t protected_data_size)
{
	uint8_t raw[600];
	size_t raw_len;
	char nonce_b64[32];
	char ct_b64[900];
	cJSON *msg;
	size_t olen;

	(void)protected_data_size; /* protected_data is a nul-terminated base64 string */

	if (!g_conn_open || !g_attested)
		return -1;

	if (mbedtls_base64_decode(raw, sizeof(raw), &raw_len,
				   (const unsigned char *)protected_data,
				   strlen(protected_data)) != 0 || raw_len < 12)
		return -1;

	if (mbedtls_base64_encode((unsigned char *)nonce_b64, sizeof(nonce_b64),
				   &olen, raw, 12) != 0)
		return -1;
	if (mbedtls_base64_encode((unsigned char *)ct_b64, sizeof(ct_b64),
				   &olen, raw + 12, raw_len - 12) != 0)
		return -1;

	msg = cJSON_CreateObject();
	if (!msg ||
	    !cJSON_AddStringToObject(msg, "type", "data") ||
	    !cJSON_AddStringToObject(msg, "device_id", g_device_id) ||
	    !cJSON_AddNumberToObject(msg, "seq", (double)g_last_seq) ||
	    !cJSON_AddStringToObject(msg, "nonce", nonce_b64) ||
	    !cJSON_AddStringToObject(msg, "ciphertext", ct_b64)) {
		cJSON_Delete(msg);
		return -1;
	}

	return send_json_line(msg);
}
