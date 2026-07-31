/*
 * Device-side TA security tests - the attacker's Host CA.
 *
 * Runs INSIDE the QEMU guest, as root, and attacks the confidential_iot TA the
 * way a root-compromised Normal World would. It is the mirror image of
 * CC_Server/server/tests/: those prove the server's verifier REJECTS forged
 * evidence; these prove the device never PRODUCES it.
 *
 * It deliberately does not reuse edge_device.c. That file is the honest Host, and
 * an honest Host is exactly what we are not simulating: this one opens its own
 * TEEC context, invokes commands out of order, feeds them malformed parameters,
 * substitutes keys it generated itself, and rewrites /lib/optee_armtz. The
 * duplicated TEEC boilerplate is the price of not being constrained by the real
 * client's control flow.
 *
 * Usage (see docs/ATTESTATION_TESTING.md):
 *   optee_example_confidential_iot_tests          # all tests
 *   optee_example_confidential_iot_tests -t 3     # one test
 *   optee_example_confidential_iot_tests -l       # list
 *
 * Exit code is the number of failed checks (capped at 125). The last line is
 * always CIOT_TESTS_DONE=<failures>, matching provision-device.sh's
 * CIOT_PROVISION_DONE= convention so a tmux-driven runner can wait on it.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tee_client_api.h>

#include <confidential_iot_ta.h>
#include <ciot_probe_ta.h>
#include <ciot_rogue_ta.h>

#include "crypto_check.h"

/*
 * TEE_ERROR_SIGNATURE_INVALID has no TEEC_ mirror in tee_client_api.h, but the
 * TA's return code reaches us verbatim. From
 * optee_os/lib/libutee/include/tee_api_defines.h.
 */
#define CIOT_TEE_ERROR_SIGNATURE_INVALID	0xFFFF3072

#define TA_INSTALL_DIR		"/lib/optee_armtz"
#define GENUINE_TA_PATH		TA_INSTALL_DIR "/7d9f6d20-5f11-4d0c-9a17-61c9c91c0001.ta"
#define PROBE_TA_PATH		TA_INSTALL_DIR "/7d9f6d20-5f11-4d0c-9a17-61c9c91c0004.ta"
#define ROGUE_TA_PATH		TA_INSTALL_DIR "/7d9f6d20-5f11-4d0c-9a17-61c9c91c0003.ta"

/*
 * The sensor_link PTA, from project/optee_os_ext/lib/libutee/include/
 * pta_sensor_link.h. Duplicated rather than included: that header lives in the
 * optee_os tree, which sync-project.sh copies somewhere entirely different from
 * optee_examples, so the path does not exist at build time from here. Keep the
 * two in step - the UUID allocation table in ciot_probe_ta.h lists both.
 */
#define PTA_SENSOR_LINK_UUID_LOCAL \
	{ 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x02 } }
#define GENUINE_TA_BACKUP	"/tmp/ciot-genuine-ta.bak"

#define DEVICE_CONF_PATH	"/etc/confidential_iot/device.conf"

/*
 * A device_id that is certainly not this device's, for the rebinding and
 * wrong-identity cases. Two of them, because the tests must still work when the
 * device under test happens to be called iot-edge-99 - see pick_foreign_id().
 */
#define FOREIGN_DEVICE_ID	"iot-edge-99"
#define FOREIGN_DEVICE_ID_ALT	"iot-edge-98"

/* ---- harness ------------------------------------------------------------- */

static int g_pass;
static int g_fail;

/* Record a failure that is not a simple boolean check - used where the failing
 * case needs to say more than its assertion did. */
static void fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("    FAIL  ");
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
	g_fail++;
}

/* Record one check. Returns the condition so callers can bail out of a
 * sequence whose remaining steps would be meaningless. */
static int expect(int cond, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf(cond ? "    ok    " : "    FAIL  ");
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);

	if (cond)
		g_pass++;
	else
		g_fail++;
	return cond;
}

static void note(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("    ..    ");
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}

/*
 * Readable names for every TEEC_ERROR_* in tee_client_api.h, not just the ones
 * these tests assert on. The unexpected code is exactly the one worth naming:
 * a bare "?" on a failing line costs a rebuild to identify, which is precisely
 * what happened the first time this suite ran for real.
 */
static const char *res_name(TEEC_Result res)
{
	switch (res) {
	case TEEC_SUCCESS:			return "TEEC_SUCCESS";
	case TEEC_ERROR_GENERIC:		return "GENERIC";
	case TEEC_ERROR_ACCESS_DENIED:		return "ACCESS_DENIED";
	case TEEC_ERROR_CANCEL:			return "CANCEL";
	case TEEC_ERROR_ACCESS_CONFLICT:	return "ACCESS_CONFLICT";
	case TEEC_ERROR_EXCESS_DATA:		return "EXCESS_DATA";
	case TEEC_ERROR_BAD_FORMAT:		return "BAD_FORMAT";
	case TEEC_ERROR_BAD_PARAMETERS:		return "BAD_PARAMETERS";
	case TEEC_ERROR_BAD_STATE:		return "BAD_STATE";
	case TEEC_ERROR_ITEM_NOT_FOUND:		return "ITEM_NOT_FOUND";
	case TEEC_ERROR_NOT_IMPLEMENTED:	return "NOT_IMPLEMENTED";
	case TEEC_ERROR_NOT_SUPPORTED:		return "NOT_SUPPORTED";
	case TEEC_ERROR_NO_DATA:		return "NO_DATA";
	case TEEC_ERROR_OUT_OF_MEMORY:		return "OUT_OF_MEMORY";
	case TEEC_ERROR_BUSY:			return "BUSY";
	case TEEC_ERROR_COMMUNICATION:		return "COMMUNICATION";
	case TEEC_ERROR_SECURITY:		return "SECURITY";
	case TEEC_ERROR_SHORT_BUFFER:		return "SHORT_BUFFER";
	case TEEC_ERROR_EXTERNAL_CANCEL:	return "EXTERNAL_CANCEL";
	case TEEC_ERROR_TARGET_DEAD:		return "TARGET_DEAD";
	case TEEC_ERROR_STORAGE_NO_SPACE:	return "STORAGE_NO_SPACE";
	case TEEC_ERROR_STORAGE_NOT_AVAILABLE:	return "STORAGE_NOT_AVAILABLE";
	case CIOT_TEE_ERROR_SIGNATURE_INVALID:	return "SIGNATURE_INVALID";
	default:				return "?";
	}
}

/* Assert a command returned exactly `want`. */
static int expect_res(TEEC_Result got, TEEC_Result want, const char *what)
{
	return expect(got == want, "%s -> %s (0x%08x)%s", what, res_name(got),
		      (unsigned)got,
		      got == want ? "" : " [expected a different code]");
}

/* ---- TEEC plumbing ------------------------------------------------------- */

struct ta_conn {
	TEEC_Context ctx;
	TEEC_Session sess;
	int open;
};

static TEEC_Result ta_connect(struct ta_conn *c, TEEC_UUID uuid,
			      uint32_t *origin)
{
	TEEC_Result res;
	uint32_t org = 0;

	memset(c, 0, sizeof(*c));

	res = TEEC_InitializeContext(NULL, &c->ctx);
	if (res != TEEC_SUCCESS) {
		if (origin)
			*origin = 0;
		return res;
	}

	res = TEEC_OpenSession(&c->ctx, &c->sess, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &org);
	if (origin)
		*origin = org;
	if (res != TEEC_SUCCESS) {
		TEEC_FinalizeContext(&c->ctx);
		return res;
	}

	c->open = 1;
	return TEEC_SUCCESS;
}

static void ta_disconnect(struct ta_conn *c)
{
	if (!c->open)
		return;
	TEEC_CloseSession(&c->sess);
	TEEC_FinalizeContext(&c->ctx);
	c->open = 0;
}

static TEEC_Result ta_invoke(struct ta_conn *c, uint32_t cmd,
			     TEEC_Operation *op)
{
	uint32_t origin = 0;

	return TEEC_InvokeCommand(&c->sess, cmd, op, &origin);
}

/* Open a session purely to see whether it can be opened. */
static TEEC_Result try_open(TEEC_UUID uuid, uint32_t *origin)
{
	struct ta_conn c;
	TEEC_Result res = ta_connect(&c, uuid, origin);

	ta_disconnect(&c);
	return res;
}

/* ---- TA command wrappers ------------------------------------------------- */

/* CMD 6: mint (first call) or re-export the sealed TA identity public key. */
static TEEC_Result cmd_ta_identity(struct ta_conn *c, const char *device_id,
				   size_t id_len, uint8_t *out, size_t out_len,
				   size_t *out_written)
{
	TEEC_Operation op;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)device_id;
	op.params[0].tmpref.size = id_len;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = out_len;

	res = ta_invoke(c, TA_CONFIDENTIAL_IOT_CMD_GENERATE_TA_IDENTITY, &op);
	if (out_written)
		*out_written = op.params[1].tmpref.size;
	return res;
}

/*
 * CMD 3: ephemeral ECDH public key + evidence block
 * (transcript hash 32 || ta_sig 64).
 */
static TEEC_Result cmd_evidence(struct ta_conn *c,
				const uint8_t *nonce, size_t nonce_len,
				const uint8_t *server_pub, size_t server_pub_len,
				uint8_t *device_pub, size_t device_pub_len,
				uint8_t *evidence, size_t evidence_len)
{
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = device_pub;
	op.params[0].tmpref.size = device_pub_len;
	op.params[1].tmpref.buffer = (void *)nonce;
	op.params[1].tmpref.size = nonce_len;
	op.params[2].tmpref.buffer = (void *)server_pub;
	op.params[2].tmpref.size = server_pub_len;
	op.params[3].tmpref.buffer = evidence;
	op.params[3].tmpref.size = evidence_len;

	return ta_invoke(c, TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE,
			 &op);
}

/* CMD 4: server authentication + session key derivation. */
static TEEC_Result cmd_handshake_complete(struct ta_conn *c,
					  const uint8_t *server_ecdh_pub,
					  const uint8_t *nonce, size_t nonce_len,
					  const uint8_t *server_id_pub,
					  const uint8_t *sig)
{
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);
	op.params[0].tmpref.buffer = (void *)server_ecdh_pub;
	op.params[0].tmpref.size = TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE;
	op.params[1].tmpref.buffer = (void *)nonce;
	op.params[1].tmpref.size = nonce_len;
	op.params[2].tmpref.buffer = (void *)server_id_pub;
	op.params[2].tmpref.size = TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE;
	op.params[3].tmpref.buffer = (void *)sig;
	op.params[3].tmpref.size = TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE;

	return ta_invoke(c, TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE, &op);
}

/* CMD 1: read a sensor sample and seal it under the session key. */
static TEEC_Result cmd_read_and_protect(struct ta_conn *c)
{
	TEEC_Operation op;
	uint8_t nonce[12];
	uint8_t ct[512];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = sizeof(nonce);
	op.params[1].tmpref.buffer = ct;
	op.params[1].tmpref.size = sizeof(ct);

	return ta_invoke(c, TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT, &op);
}

/* ---- local config -------------------------------------------------------- */

/*
 * The device_id must be BYTE-IDENTICAL to the one sealed with the TA identity,
 * or test 3's positive control fails for an uninteresting reason. So read it the
 * same way edge_device.c's load_config() does (same file, same key, same
 * CIOT_DEVICE_ID override).
 *
 * Returns 1 if the id was actually FOUND, 0 if `out` is edge_device.c's built-in
 * default guess. Callers must not invoke CMD 6 on a guess: the sealed identity is
 * first-write-wins, so guessing wrong on an unprovisioned device would seal the
 * key to the wrong id and every later provisioning attempt would then hit
 * TEE_ERROR_ACCESS_CONFLICT until the secure storage is wiped. Tests are allowed
 * to break, not to brick.
 */
static int load_device_id(char *out, size_t out_len)
{
	FILE *f;
	char line[256];
	const char *env;
	int found = 0;

	snprintf(out, out_len, "%s", "iot-edge-01");

	f = fopen(DEVICE_CONF_PATH, "r");
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

			if (strcmp(line, "device_id") == 0) {
				snprintf(out, out_len, "%s", eq + 1);
				found = 1;
			}
		}
		fclose(f);
	}

	env = getenv("CIOT_DEVICE_ID");
	if (env) {
		snprintf(out, out_len, "%s", env);
		found = 1;
	}

	return found;
}

/*
 * Shared precondition for every test that drives CMD 6. See load_device_id().
 */
static int device_id_is_known(char *out, size_t out_len)
{
	if (load_device_id(out, out_len))
		return 1;

	fail("no device_id in %s and no CIOT_DEVICE_ID - provision the device first",
	     DEVICE_CONF_PATH);
	note("skipped: CMD 6 seals the TA identity first-write-wins, so running it");
	note("on a guessed device_id would need a secure-storage wipe to undo");
	return 0;
}

/*
 * A device_id that is definitely not this device's. Two fixed candidates rather
 * than deriving one from device_id: a derived id could collide with the maximum
 * length the TA accepts, and then "the TA rejected it" would be about the length
 * rather than about the identity binding.
 */
static void pick_foreign_id(const char *device_id, char *out, size_t out_len)
{
	snprintf(out, out_len, "%s", FOREIGN_DEVICE_ID);
	if (strcmp(out, device_id) == 0)
		snprintf(out, out_len, "%s", FOREIGN_DEVICE_ID_ALT);
}

/* ---- file helpers (test 1) ----------------------------------------------- */

static int file_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

/* Slurp a whole file. Caller frees. */
static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf = NULL;
	long len;

	if (!f)
		return NULL;

	if (fseek(f, 0, SEEK_END) != 0)
		goto out;
	len = ftell(f);
	if (len <= 0)
		goto out;
	if (fseek(f, 0, SEEK_SET) != 0)
		goto out;

	buf = malloc((size_t)len);
	if (!buf)
		goto out;

	if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
		free(buf);
		buf = NULL;
		goto out;
	}
	*out_len = (size_t)len;
out:
	fclose(f);
	return buf;
}

/*
 * Replace a file's contents. The installed TAs are mode 444, so unlink first
 * rather than fighting the permissions - /lib/optee_armtz is a directory in the
 * initramfs and we are root.
 */
static int write_file(const char *path, const uint8_t *buf, size_t len)
{
	FILE *f;

	unlink(path);
	f = fopen(path, "wb");
	if (!f)
		return -1;

	if (fwrite(buf, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	if (fclose(f) != 0)
		return -1;

	/* Match the mode the Buildroot package installs with. */
	if (chmod(path, 0444) != 0)
		return -1;
	return 0;
}

static int copy_file(const char *src, const char *dst)
{
	size_t len = 0;
	uint8_t *buf = read_file(src, &len);
	int rc;

	if (!buf)
		return -1;
	rc = write_file(dst, buf, len);
	free(buf);
	return rc;
}

/* ---- test 1: UUID mimicry ------------------------------------------------ */

/*
 * Part A of docs/TA_IDENTITY_IMPLEMENTATION.md, made executable: the OP-TEE core
 * verifies every TA against the public key baked into it (keys/ciot_ta.pem, and
 * measured into PCR0), so an attacker with root can put whatever they like in
 * /lib/optee_armtz and none of it will load.
 *
 * This matters beyond "a tampered TA won't run": secure storage is scoped to the
 * TA UUID, so a loadable TA carrying the genuine UUID would be handed the sealed
 * ciot.ta.identity key - which is why Part A gates Part B, and why the mimicry
 * case below is the one that counts.
 *
 * Everything here happens in RAM: the rootfs is an initramfs, so even a crash
 * mid-test is undone by a reboot. The genuine TA is backed up first, restored
 * after every leg, and re-opened at the end as a control.
 */
static void test_uuid_mimicry(void)
{
	const TEEC_UUID genuine = TA_CONFIDENTIAL_IOT_UUID;
	const TEEC_UUID rogue = TA_CIOT_ROGUE_UUID;
	uint32_t origin = 0;
	TEEC_Result res;
	uint8_t *ta = NULL;
	size_t ta_len = 0;
	int restored;

	/* Fixtures must actually be present, or "it did not load" would pass for
	 * the wrong reason - a missing file fails identically to a rejected
	 * signature. */
	if (!expect(file_exists(GENUINE_TA_PATH), "genuine TA is installed at %s",
		    GENUINE_TA_PATH))
		return;
	if (!expect(file_exists(ROGUE_TA_PATH),
		    "rogue TA fixture is installed at %s (rebuild if missing)",
		    ROGUE_TA_PATH))
		return;

	/* (a) control: the real TA loads. */
	res = try_open(genuine, &origin);
	if (!expect(res == TEEC_SUCCESS, "genuine UUID opens -> %s (control)",
		    res_name(res)))
		return;

	/* Back up before touching anything. */
	if (!expect(copy_file(GENUINE_TA_PATH, GENUINE_TA_BACKUP) == 0,
		    "backed up the genuine TA to %s", GENUINE_TA_BACKUP))
		return;

	/* (b) the rogue, under its own UUID: signed with attacker_ta.pem, so the
	 * core's verifier must refuse it outright. */
	res = try_open(rogue, &origin);
	expect(res != TEEC_SUCCESS,
	       "rogue UUID ...0003 (attacker-signed) refused -> %s (0x%08x), origin %u",
	       res_name(res), (unsigned)res, (unsigned)origin);

	/* (c) THE MIMICRY: the attacker plants their own TA at the genuine UUID's
	 * path. The core checks the signature before it ever compares the UUID in
	 * the header, so this dies at verification. */
	if (expect(copy_file(ROGUE_TA_PATH, GENUINE_TA_PATH) == 0,
		   "planted the attacker-signed TA at the genuine UUID's path")) {
		res = try_open(genuine, &origin);
		expect(res != TEEC_SUCCESS,
		       "genuine UUID with an attacker-signed TA behind it refused -> %s (0x%08x)",
		       res_name(res), (unsigned)res);
		if (res == TEEC_SUCCESS)
			note("if this passed, check whether the core reused an already-loaded instance");
	}

	restored = copy_file(GENUINE_TA_BACKUP, GENUINE_TA_PATH) == 0;
	if (!expect(restored, "restored the genuine TA"))
		goto out;

	/* (d) tampering instead of re-signing: flip one byte of the real TA. */
	ta = read_file(GENUINE_TA_BACKUP, &ta_len);
	if (expect(ta != NULL && ta_len > 64, "read the genuine TA (%zu bytes)",
		   ta_len)) {
		ta[ta_len / 2] ^= 0xff;
		if (expect(write_file(GENUINE_TA_PATH, ta, ta_len) == 0,
			   "planted a byte-flipped copy of the genuine TA")) {
			res = try_open(genuine, &origin);
			expect(res != TEEC_SUCCESS,
			       "byte-flipped genuine TA refused -> %s (0x%08x)",
			       res_name(res), (unsigned)res);
		}
	}

	expect(copy_file(GENUINE_TA_BACKUP, GENUINE_TA_PATH) == 0,
	       "restored the genuine TA");

out:
	free(ta);

	/* Final control. A failed restore must never be mistaken for a pass, so
	 * this check is the last word on the whole test. */
	res = try_open(genuine, &origin);
	expect(res == TEEC_SUCCESS,
	       "genuine UUID opens again after restore -> %s (control)",
	       res_name(res));
	if (res != TEEC_SUCCESS)
		note("RESTORE FAILED - reboot the guest; %s holds the original",
		     GENUINE_TA_BACKUP);
}

/* ---- test 2: secure storage is scoped to the TA UUID --------------------- */

/*
 * The premise the whole TA-identity design rests on. If any other TA could open
 * ciot.ta.identity, the private signing key would buy nothing - an attacker would
 * not need to mimic the UUID at all, just load a TA of their own.
 *
 * The prober is signed with the PROJECT key, so it loads normally: the only thing
 * separating it from the real TA is its UUID, which is precisely the variable
 * under test.
 */
static void test_storage_scoping(void)
{
	static const char *const foreign_objects[] = {
		TA_CONFIDENTIAL_IOT_TA_IDENTITY_OBJID,
		"ciot.sensor.psk",
		TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID,
	};
	const TEEC_UUID probe = TA_CIOT_PROBE_UUID;
	struct ta_conn c;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;
	size_t i;

	/* Same reason test 1 checks its fixtures first: a missing .ta and a
	 * rejected one both surface as "the session would not open". */
	if (!expect(file_exists(PROBE_TA_PATH),
		    "prober TA fixture is installed at %s (rebuild if missing)",
		    PROBE_TA_PATH))
		return;

	res = ta_connect(&c, probe, &origin);
	if (!expect(res == TEEC_SUCCESS, "prober TA ...0004 opens -> %s (0x%08x), origin %u",
		    res_name(res), (unsigned)res, (unsigned)origin)) {
		note("the fixture is present, so this is a load failure, not a missing file -");
		note("the secure console (tmux window 0) logs why OP-TEE refused it");
		return;
	}

	for (i = 0; i < sizeof(foreign_objects) / sizeof(foreign_objects[0]); i++) {
		const char *id = foreign_objects[i];

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_VALUE_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = (void *)id;
		op.params[0].tmpref.size = strlen(id);

		res = ta_invoke(&c, TA_CIOT_PROBE_CMD_OPEN_FOREIGN_OBJECT, &op);
		if (!expect(res == TEEC_SUCCESS, "probe of \"%s\" ran -> %s", id,
			    res_name(res)))
			continue;

		expect(op.params[1].value.a == TEEC_ERROR_ITEM_NOT_FOUND,
		       "\"%s\" is invisible from another UUID -> %s", id,
		       res_name(op.params[1].value.a));
		if (op.params[1].value.a == TEEC_SUCCESS) {
			fail("another TA READ %u bytes of \"%s\" - storage isolation is broken",
			     (unsigned)op.params[1].value.b, id);
			/* The prober deletes and re-probes anything carrying its
			 * own marker, so litter cannot reach here - but print the
			 * real size anyway, because "is this a breach or a broken
			 * fixture" is the first question this line raises. */
			note("for reference, a genuine sealed %s is %d bytes",
			     TA_CONFIDENTIAL_IOT_TA_IDENTITY_OBJID,
			     TA_CONFIDENTIAL_IOT_TA_IDENTITY_BLOB_SIZE);
		}
	}

	/*
	 * Control: the prober creates, reads back and deletes an object of its
	 * OWN. Proves this TA's storage works at all, so the ITEM_NOT_FOUNDs above
	 * are UUID scoping rather than a dead fixture.
	 *
	 * Under its own object id, NOT one of the ids probed above. Sharing the
	 * name was the original design and it was actively harmful: a control run
	 * that died before deleting left an object of ours under a foreign name,
	 * and the next run's probe opened it and declared isolation broken.
	 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)PROBE_CONTROL_OBJID;
	op.params[0].tmpref.size = strlen(PROBE_CONTROL_OBJID);

	res = ta_invoke(&c, TA_CIOT_PROBE_CMD_SELF_ROUNDTRIP, &op);
	if (expect(res == TEEC_SUCCESS, "self round-trip ran -> %s", res_name(res))) {
		expect(op.params[1].value.a == TEEC_SUCCESS,
		       "prober can create/read/delete its OWN \"%s\" -> %s (control)",
		       PROBE_CONTROL_OBJID, res_name(op.params[1].value.a));
	} else if (res == TEEC_ERROR_TARGET_DEAD) {
		note("the prober panicked - deleting a persistent object needs");
		note("TEE_DATA_FLAG_ACCESS_WRITE_META, or the delete call panics");
	}

	ta_disconnect(&c);

	/*
	 * The same scoping question one level down: the sensor_link PTA owns the
	 * secure UART the Sensor Module talks over, and permits exactly one caller
	 * (SENSOR_LINK_ALLOWED_CALLER_UUID = the confidential_iot TA). A Host
	 * process must not be able to open it and read sensor plaintext straight
	 * off the link, bypassing the TA's encryption entirely.
	 *
	 * This check exists because an earlier version of this fixture was
	 * accidentally built with the PTA's UUID, and the PTA refused it - which is
	 * exactly the property worth asserting on purpose.
	 */
	{
		const TEEC_UUID sensor_pta = PTA_SENSOR_LINK_UUID_LOCAL;
		uint32_t pta_origin = 0;

		res = try_open(sensor_pta, &pta_origin);
		expect(res != TEEC_SUCCESS,
		       "sensor_link PTA refuses a Normal-World caller -> %s (0x%08x), origin %u",
		       res_name(res), (unsigned)res, (unsigned)pta_origin);
	}
}

/* ---- test 3: ta_sig cannot cover an attacker's key ----------------------- */

/* Render a digest as lowercase hex and compare against a literal. */
static int hex_eq(const uint8_t digest[32], const char *expect_hex)
{
	char hex[65];
	int i;

	for (i = 0; i < 32; i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	return strcmp(hex, expect_hex) == 0;
}

/*
 * Known-answer test for this file's own pre-image builders, run before they are
 * used to judge the TA.
 *
 * The vectors are the ones CC_Server/server/tests/test_attestation.py pins in
 * test_ta_identity_preimage_is_byte_exact, so this is the C/Python parity lock
 * made executable ON THE DEVICE. Without it, a one-byte disagreement in
 * crypto_check.c would surface as "the TA's signature does not verify", sending
 * whoever is debugging straight at the TA's ECDSA - which is exactly the wild
 * goose chase §6.1 of docs/TA_IDENTITY_IMPLEMENTATION.md records.
 */
static void preimage_known_answer_check(void)
{
	uint8_t nonce[32];
	uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t digest[32];
	int i;

	for (i = 0; i < 32; i++)
		nonce[i] = (uint8_t)i;			/* bytes(range(32)) */
	memset(server_pub, 0x00, sizeof(server_pub));
	server_pub[0] = 0x04;				/* b"\x04" + bytes(64) */
	memset(device_pub, 0xaa, sizeof(device_pub));
	device_pub[0] = 0x04;				/* b"\x04" + 0xAA * 64 */

	if (expect(cc_ta_identity_digest(nonce, sizeof(nonce), server_pub,
					 device_pub, "iot-edge-01", digest) == 0,
		   "known-answer: built the TA-identity pre-image"))
		expect(hex_eq(digest,
			      "b34347ceed037083e6678f4ca1ee3306388e8da501cae328cf60c59fac294c96"),
		       "known-answer: TA-identity digest matches the server's pinned value");

	if (expect(cc_transcript_hash(nonce, sizeof(nonce), server_pub,
				      device_pub, digest) == 0,
		   "known-answer: built the transcript hash"))
		expect(hex_eq(digest,
			      "60105b236bd07b56f3b541cae7be842f305a6edce8281ec3e35fb2d29aae2cf1"),
		       "known-answer: transcript digest matches SHA-256(nonce || server_pub || device_pub)");
}

/*
 * The compromised-Host bypass, driven from the device end.
 *
 * The AK lives in the fTPM at a fixed handle with no auth value, and the quote is
 * assembled by the untrusted Host - so root CAN generate its own ECDH keypair and
 * have the real fTPM quote it under the real PCR0. What it cannot do is produce
 * ta_sig over that key, because the signing key is sealed to the genuine TA's
 * UUID (and test 1 shows you cannot become that UUID).
 *
 * The test plays the server: it computes the same pre-image
 * CC_Server/server/attestation.py builds and verifies the TA's real signature
 * against it. The positive control doubles as a C/Python parity check against
 * live TA output, rather than the known-answer vector the server suite pins.
 */
static void test_fake_attestation(void)
{
	const TEEC_UUID genuine = TA_CONFIDENTIAL_IOT_UUID;
	struct ta_conn c;
	TEEC_Result res;
	uint32_t origin = 0;
	char device_id[64];
	char foreign_id[64];
	uint8_t ta_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t evil_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t device_pub2[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t evidence[TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE];
	uint8_t evidence2[TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE];
	uint8_t nonce[32];
	uint8_t nonce2[32];
	uint8_t digest[32];
	uint8_t transcript[32];
	const uint8_t *ta_sig = evidence + TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE;
	size_t pub_len = 0;

	/* Check the yardstick before measuring anything with it. */
	preimage_known_answer_check();

	if (!device_id_is_known(device_id, sizeof(device_id)))
		return;
	note("device_id = \"%s\"", device_id);

	if (!expect(cc_random(nonce, sizeof(nonce)) == 0 &&
		    cc_random(nonce2, sizeof(nonce2)) == 0 &&
		    cc_gen_p256_pub(server_pub) == 0 &&
		    cc_gen_p256_pub(evil_pub) == 0,
		    "generated attacker nonces and P-256 keys"))
		return;

	res = ta_connect(&c, genuine, &origin);
	if (!expect(res == TEEC_SUCCESS, "genuine TA opens -> %s", res_name(res)))
		return;

	/* Idempotent: re-exports the sealed key if provisioning already ran. */
	res = cmd_ta_identity(&c, device_id, strlen(device_id), ta_pub,
			      sizeof(ta_pub), &pub_len);
	if (!expect(res == TEEC_SUCCESS && pub_len == sizeof(ta_pub) &&
		    ta_pub[0] == 0x04,
		    "CMD 6 returns a 65-byte SEC1 TA identity key -> %s",
		    res_name(res)))
		goto out;

	res = cmd_evidence(&c, nonce, sizeof(nonce), server_pub,
			   sizeof(server_pub), device_pub, sizeof(device_pub),
			   evidence, sizeof(evidence));
	if (!expect(res == TEEC_SUCCESS, "CMD 3 produces evidence -> %s",
		    res_name(res))) {
		if (res == TEEC_ERROR_BAD_STATE)
			note("BAD_STATE here means no TA identity is sealed - run provision-device.sh");
		goto out;
	}

	expect(device_pub[0] == 0x04,
	       "device_ecdh_pub is an uncompressed SEC1 point");

	/* Control 1: the transcript hash really is over this session's keys, so
	 * the fTPM quote's qualifying data commits to the TA's key. */
	if (expect(cc_transcript_hash(nonce, sizeof(nonce), server_pub,
				      device_pub, transcript) == 0,
		   "recomputed the transcript hash"))
		expect(memcmp(transcript, evidence, sizeof(transcript)) == 0,
		       "evidence[0..32) == SHA-256(nonce || server_pub || device_pub)");

	/* Control 2: the real signature verifies over the real pre-image. This is
	 * the C/Python parity lock, against live TA output. */
	if (!expect(cc_ta_identity_digest(nonce, sizeof(nonce), server_pub,
					  device_pub, device_id, digest) == 0,
		    "built the TA-identity pre-image"))
		goto out;
	expect(cc_ecdsa_p256_verify(ta_pub, digest, ta_sig) == 0,
	       "ta_sig verifies under the sealed TA key over the real pre-image (control)");

	/*
	 * Attack A - the bypass itself. Root swaps in an ECDH key whose private
	 * half it holds and gets the fTPM to quote it. No ta_sig covers it.
	 */
	if (expect(cc_ta_identity_digest(nonce, sizeof(nonce), server_pub,
					 evil_pub, device_id, digest) == 0,
		   "built the pre-image with an attacker-held ECDH key"))
		expect(cc_ecdsa_p256_verify(ta_pub, digest, ta_sig) != 0,
		       "ta_sig does NOT cover the attacker's ECDH key");

	/* Attack B - freshness. A signature from an earlier session must not
	 * carry over to a new challenge. */
	res = cmd_evidence(&c, nonce2, sizeof(nonce2), server_pub,
			   sizeof(server_pub), device_pub2, sizeof(device_pub2),
			   evidence2, sizeof(evidence2));
	if (expect(res == TEEC_SUCCESS, "CMD 3 again with a fresh nonce -> %s",
		   res_name(res))) {
		expect(memcmp(device_pub, device_pub2, sizeof(device_pub)) != 0,
		       "each session gets a fresh ephemeral ECDH key");
		if (expect(cc_ta_identity_digest(nonce2, sizeof(nonce2),
						 server_pub, device_pub2,
						 device_id, digest) == 0,
			   "built session 2's pre-image"))
			expect(cc_ecdsa_p256_verify(ta_pub, digest, ta_sig) != 0,
			       "session 1's ta_sig does NOT verify against session 2");
	}

	/* Attack C - per-device binding. device_id comes from the sealed identity
	 * object, not from anything the Host asserts, so claiming to be another
	 * device breaks the signature. */
	pick_foreign_id(device_id, foreign_id, sizeof(foreign_id));

	if (expect(cc_ta_identity_digest(nonce, sizeof(nonce), server_pub,
					 device_pub, foreign_id, digest) == 0,
		   "built the pre-image under device_id \"%s\"", foreign_id))
		expect(cc_ecdsa_p256_verify(ta_pub, digest, ta_sig) != 0,
		       "ta_sig does NOT verify under another device's id");

out:
	ta_disconnect(&c);
}

/* ---- test 4: the gates live in the TA ------------------------------------ */

/*
 * "Fake an attestation" from the Host's side: the Host is the one that talks to
 * the server, so it can simply claim the server said ok. It gains nothing,
 * because both preconditions for the data path are checked inside the TA - the
 * sensor must have authenticated, and the session key must have been derived by a
 * handshake in which the TA itself authenticated the server.
 *
 * SAFETY, and it is load-bearing: the server identity key is pinned Trust-On-
 * First-Use. Presenting a VALIDLY SIGNED attacker key while nothing is pinned
 * would pin it and permanently break this device's server authentication. So the
 * signature here is always random, and the return code tells us which state we
 * are in without ever risking a write:
 *   ACCESS_CONFLICT    -> a key is pinned; impersonation was rejected on sight.
 *   SIGNATURE_INVALID  -> nothing pinned yet; authenticate_server() verifies
 *                         before it pins, so nothing was written either.
 * Both are passes.
 */
static void test_host_cannot_fake_a_session(void)
{
	const TEEC_UUID genuine = TA_CONFIDENTIAL_IOT_UUID;
	struct ta_conn c;
	TEEC_Result res;
	uint32_t origin = 0;
	uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t attacker_id_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t evidence[TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE];
	uint8_t nonce[32];
	uint8_t forged_sig[TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE];

	if (!expect(cc_random(nonce, sizeof(nonce)) == 0 &&
		    cc_random(forged_sig, sizeof(forged_sig)) == 0 &&
		    cc_gen_p256_pub(server_pub) == 0 &&
		    cc_gen_p256_pub(attacker_id_pub) == 0,
		    "generated a forged signature and an attacker server key"))
		return;

	/* A fresh session is a fresh TA instance (TA_FLAGS has no
	 * SINGLE_INSTANCE), so none of the real client's state carries over. */
	res = ta_connect(&c, genuine, &origin);
	if (!expect(res == TEEC_SUCCESS, "genuine TA opens -> %s", res_name(res)))
		return;

	/* No attestation, no sensor auth: the data path must be shut. */
	res = cmd_read_and_protect(&c);
	expect_res(res, TEEC_ERROR_BAD_STATE,
		   "CMD 1 with no attested session at all");

	/* Skipping straight to the key derivation, without CMD 3. */
	res = cmd_handshake_complete(&c, server_pub, nonce, sizeof(nonce),
				     attacker_id_pub, forged_sig);
	expect_res(res, TEEC_ERROR_BAD_STATE, "CMD 4 without a prior CMD 3");

	/* Now do it "properly" as far as the Host can: real evidence, then lie
	 * about the server. */
	res = cmd_evidence(&c, nonce, sizeof(nonce), server_pub,
			   sizeof(server_pub), device_pub, sizeof(device_pub),
			   evidence, sizeof(evidence));
	if (!expect(res == TEEC_SUCCESS, "CMD 3 succeeds -> %s", res_name(res)))
		goto out;

	res = cmd_handshake_complete(&c, server_pub, nonce, sizeof(nonce),
				     attacker_id_pub, forged_sig);
	expect(res == CIOT_TEE_ERROR_SIGNATURE_INVALID ||
	       res == TEEC_ERROR_ACCESS_CONFLICT,
	       "CMD 4 with a forged server signature rejected -> %s (0x%08x)",
	       res_name(res), (unsigned)res);

	if (res == TEEC_ERROR_ACCESS_CONFLICT)
		note("a server key is pinned - impersonation rejected before verification");
	else if (res == CIOT_TEE_ERROR_SIGNATURE_INVALID)
		note("no server key pinned yet - rejected at verification, nothing written");

	/* The decisive one: no session key was derived, so the data path is still
	 * shut even after a handshake the Host considers "complete". */
	res = cmd_read_and_protect(&c);
	expect_res(res, TEEC_ERROR_BAD_STATE,
		   "CMD 1 after the failed handshake (no session key derived)");

out:
	ta_disconnect(&c);
}

/* ---- test 5: the sealed identity is immutable ---------------------------- */

/*
 * The sealed TA identity binds a keypair to one device_id, first-write-wins. That
 * is what stops a copied secure-storage image being presented as a different
 * device, and stops the Host asserting a different identity per session.
 *
 * The second half feeds the TA malformed parameters. The bar is not just "an
 * error" but "a clean GP error and the TA is still alive": TEE_AsymmetricSignDigest
 * PANICS on anything except SHORT_BUFFER (see §7 of the implementation notes), so
 * TEEC_ERROR_TARGET_DEAD anywhere here is a real finding.
 */
static void test_identity_is_immutable(void)
{
	const TEEC_UUID genuine = TA_CONFIDENTIAL_IOT_UUID;
	struct ta_conn c;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;
	char device_id[64];
	char foreign_id[64];
	char long_id[TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX + 1];
	uint8_t pub1[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t pub2[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t small[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE - 1];
	uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t evidence[TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE];
	uint8_t server_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t long_nonce[TA_CONFIDENTIAL_IOT_NONCE_MAX + 1];
	size_t len1 = 0;
	size_t len2 = 0;

	if (!device_id_is_known(device_id, sizeof(device_id)))
		return;

	if (!expect(cc_random(long_nonce, sizeof(long_nonce)) == 0 &&
		    cc_gen_p256_pub(server_pub) == 0,
		    "generated oversized-nonce and server-key inputs"))
		return;

	res = ta_connect(&c, genuine, &origin);
	if (!expect(res == TEEC_SUCCESS, "genuine TA opens -> %s", res_name(res)))
		return;

	/* Idempotent re-export: same id in, same key out. */
	res = cmd_ta_identity(&c, device_id, strlen(device_id), pub1,
			      sizeof(pub1), &len1);
	if (!expect(res == TEEC_SUCCESS && len1 == sizeof(pub1),
		    "CMD 6 with the real device_id -> %s", res_name(res)))
		goto out;

	res = cmd_ta_identity(&c, device_id, strlen(device_id), pub2,
			      sizeof(pub2), &len2);
	if (expect(res == TEEC_SUCCESS && len2 == sizeof(pub2),
		   "CMD 6 again with the real device_id -> %s", res_name(res)))
		expect(memcmp(pub1, pub2, sizeof(pub1)) == 0,
		       "re-provisioning re-exports the identical key (idempotent)");

	/* Rebinding to another identity must be refused, not silently accepted -
	 * that is what makes a stolen storage image useless under a new name. */
	pick_foreign_id(device_id, foreign_id, sizeof(foreign_id));

	res = cmd_ta_identity(&c, foreign_id, strlen(foreign_id), pub2,
			      sizeof(pub2), NULL);
	expect_res(res, TEEC_ERROR_ACCESS_CONFLICT,
		   "CMD 6 rebinding to another device_id");

	/* ...and the refusal left the sealed key untouched. */
	memset(pub2, 0, sizeof(pub2));
	res = cmd_ta_identity(&c, device_id, strlen(device_id), pub2,
			      sizeof(pub2), &len2);
	if (expect(res == TEEC_SUCCESS, "CMD 6 with the real device_id again -> %s",
		   res_name(res)))
		expect(memcmp(pub1, pub2, sizeof(pub1)) == 0,
		       "the rejected rebind did not disturb the sealed key");

	/* ---- parameter shape: clean errors, no panics ---- */

	res = cmd_ta_identity(&c, device_id, 0, pub2, sizeof(pub2), NULL);
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS, "CMD 6 with a zero-length device_id");

	memset(long_id, 'a', sizeof(long_id));
	res = cmd_ta_identity(&c, long_id, sizeof(long_id), pub2, sizeof(pub2),
			      NULL);
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS,
		   "CMD 6 with a device_id one byte over the maximum");

	res = cmd_ta_identity(&c, device_id, strlen(device_id), small,
			      sizeof(small), NULL);
	expect_res(res, TEEC_ERROR_SHORT_BUFFER,
		   "CMD 6 with a 64-byte output buffer");

	/* Wrong param types: the TA compares the whole packed word, so an
	 * all-NONE call must be rejected before anything is read. */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_GENERATE_TA_IDENTITY, &op);
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS, "CMD 6 with wrong param types");

	res = cmd_evidence(&c, long_nonce, sizeof(long_nonce), server_pub,
			   sizeof(server_pub), device_pub, sizeof(device_pub),
			   evidence, sizeof(evidence));
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS,
		   "CMD 3 with a nonce one byte over NONCE_MAX");

	res = cmd_evidence(&c, long_nonce, 32, server_pub,
			   sizeof(server_pub) - 1, device_pub,
			   sizeof(device_pub), evidence, sizeof(evidence));
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS,
		   "CMD 3 with a 64-byte server ECDH key");

	/* Command id 2 is the retired PROTECT_SENSOR_DATA, deliberately never
	 * reused - it must be as dead as any unknown id. */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = ta_invoke(&c, 2, &op);
	expect_res(res, TEEC_ERROR_NOT_SUPPORTED, "retired command id 2");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = ta_invoke(&c, 99, &op);
	expect_res(res, TEEC_ERROR_NOT_SUPPORTED, "unknown command id 99");

	/* Still alive, and still the same identity. */
	memset(pub2, 0, sizeof(pub2));
	res = cmd_ta_identity(&c, device_id, strlen(device_id), pub2,
			      sizeof(pub2), &len2);
	if (expect(res == TEEC_SUCCESS,
		   "the TA survived every malformed call -> %s", res_name(res)))
		expect(memcmp(pub1, pub2, sizeof(pub1)) == 0,
		       "the sealed identity is unchanged (control)");
	else if (res == TEEC_ERROR_TARGET_DEAD)
		note("TARGET_DEAD means the TA panicked - check the secure console");

out:
	ta_disconnect(&c);
}

/*
 * The sensor pre-shared key is pulled from the Sensor Module, never pushed in
 * by the Host.
 *
 * CMD 5 used to take the key as a 32-byte input memref, which handed a
 * root-compromised Host a real capability: on a device with no key sealed yet
 * it could provision one of its own choosing and pair the device to a sensor
 * IT controlled, and every downstream attestation would still verify - the AK,
 * PCR0 and ta_sig all attest to the device, firmware and TA, none of them to
 * the sensor. The command now takes no parameters at all and the TA fetches
 * the key over the secure UART itself, so that capability is gone by
 * construction rather than by policy. This test is the regression guard.
 *
 * Deliberately does NOT invoke CMD 0 as an end-to-end control. A challenge
 * flips sensor_daemon's authenticated flag, which starts the periodic reading
 * pushes; with nothing draining them they overflow the PL011 RX FIFO and
 * corrupt the link for any later run in the same boot.
 */
static void test_sensor_psk_is_pulled(void)
{
	const TEEC_UUID genuine = TA_CONFIDENTIAL_IOT_UUID;
	struct ta_conn c;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;
	uint8_t attacker_psk[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE];
	uint8_t stolen[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE];

	if (!expect(cc_random(attacker_psk, sizeof(attacker_psk)) == 0,
		    "generated an attacker-chosen sensor key"))
		return;

	res = ta_connect(&c, genuine, &origin);
	if (!expect(res == TEEC_SUCCESS, "genuine TA opens -> %s", res_name(res)))
		return;

	/* The capability that was removed: injecting a chosen key. */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = attacker_psk;
	op.params[0].tmpref.size = sizeof(attacker_psk);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET, &op);
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS,
		   "CMD 5 refuses a Host-supplied key (no input slot exists)");

	/* And the mirror image: asking the TA to hand the key back out. */
	memset(&op, 0, sizeof(op));
	memset(stolen, 0, sizeof(stolen));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = stolen;
	op.params[0].tmpref.size = sizeof(stolen);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET, &op);
	if (expect_res(res, TEEC_ERROR_BAD_PARAMETERS,
		       "CMD 5 refuses to export the key (no output slot either)")) {
		uint8_t zero[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE] = { 0 };

		expect(memcmp(stolen, zero, sizeof(stolen)) == 0,
		       "the rejected call wrote nothing into the Host's buffer");
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET, &op);
	expect_res(res, TEEC_ERROR_BAD_PARAMETERS, "CMD 5 with a value parameter");

	/*
	 * The supported shape. On a provisioned device this is a storage probe
	 * inside the TA and puts nothing on the link, so it is safe to run here
	 * and safe to run twice.
	 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET, &op);
	if (!expect(res == TEEC_SUCCESS, "CMD 5 with no parameters -> %s",
		    res_name(res))) {
		if (res == TEEC_ERROR_ACCESS_DENIED)
			note("ACCESS_DENIED means the sensor already served its one-shot key - restart sensor_daemon");
		goto out;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = ta_invoke(&c, TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET, &op);
	expect(res == TEEC_SUCCESS, "CMD 5 again is an idempotent no-op -> %s",
	       res_name(res));

out:
	ta_disconnect(&c);
}

/* ---- driver -------------------------------------------------------------- */

struct test_case {
	int id;
	const char *name;
	void (*fn)(void);
};

static const struct test_case tests[] = {
	{ 1, "UUID mimicry - a TA signed with a non-project key must not load",
	  test_uuid_mimicry },
	{ 2, "Secure storage is scoped to the TA UUID",
	  test_storage_scoping },
	{ 3, "Faked attestation - ta_sig cannot cover an attacker's ECDH key",
	  test_fake_attestation },
	{ 4, "A lying Host gains nothing - the gates live in the TA",
	  test_host_cannot_fake_a_session },
	{ 5, "The sealed device identity cannot be re-badged or reshaped",
	  test_identity_is_immutable },
	{ 6, "The sensor key is pulled from the sensor, not injected by the Host",
	  test_sensor_psk_is_pulled },
};

#define TEST_COUNT (int)(sizeof(tests) / sizeof(tests[0]))

static void usage(const char *argv0)
{
	printf("usage: %s [-t N] [-l] [-h]\n", argv0);
	printf("  -t N   run only test N (1..%d)\n", TEST_COUNT);
	printf("  -l     list the tests and exit\n");
	printf("  -h     this help\n");
	printf("\nRun as root, in the Normal-World console, after the device has\n");
	printf("been provisioned. Test 1 rewrites %s (in RAM:\n", TA_INSTALL_DIR);
	printf("the rootfs is an initramfs) and restores it afterwards.\n");
}

int main(int argc, char *argv[])
{
	int only = 0;
	int i;
	int opt;

	while ((opt = getopt(argc, argv, "t:lh")) != -1) {
		switch (opt) {
		case 't':
			only = atoi(optarg);
			if (only < 1 || only > TEST_COUNT) {
				fprintf(stderr, "no such test: %s\n", optarg);
				return 1;
			}
			break;
		case 'l':
			for (i = 0; i < TEST_COUNT; i++)
				printf("%d. %s\n", tests[i].id, tests[i].name);
			return 0;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (geteuid() != 0)
		printf("warning: not running as root - test 1 cannot rewrite %s\n",
		       TA_INSTALL_DIR);

	printf("confidential_iot device-side TA security tests\n");

	for (i = 0; i < TEST_COUNT; i++) {
		if (only && tests[i].id != only)
			continue;
		printf("\n[%d] %s\n", tests[i].id, tests[i].name);
		tests[i].fn();
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	printf("CIOT_TESTS_DONE=%d\n", g_fail);

	return g_fail > 125 ? 125 : g_fail;
}
