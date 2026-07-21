// SPDX-License-Identifier: BSD-2-Clause
/*
 * confidential_iot project: sensor_link PTA.
 *
 * Owns the secure-only UART2 added by project/patches/virt-uart2.patch
 * (QEMU virt machine, MMIO 0x090c0000, IRQ SPI 10) and speaks a small
 * length-prefixed framing protocol to the external Sensor Module process
 * (sensor_module/sensor_daemon.c) over it - see pta_sensor_link.h for the
 * wire format and command definitions.
 *
 * Security property this exists for: UART2's device-tree node is marked
 * "disabled" for Normal World (the same mechanism OP-TEE's own UART1
 * console already relies on), so Linux/the Host CA has no path to this
 * hardware at all. Only the confidential_iot TA may reach it, and only by
 * an in-process TEE_OpenTASession()/TEE_InvokeTACommand() call that never
 * leaves Secure World (see core/kernel/pseudo_ta.c's
 * tee_ta_init_pseudo_ta_session()) - so sensor bytes never transit a
 * Host-owned buffer.
 */

#include <assert.h>
#include <config.h>
#include <drivers/pl011.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <pta_sensor_link.h>
#include <string.h>
#include <trace.h>

#define PTA_NAME "sensor_link.pta"

/*
 * QEMU virt machine memmap, see project/patches/virt-uart2.patch. Hardcoded
 * here (rather than pulled from platform_config.h) because this PTA is only
 * ever built for this project's qemu_armv8a target (gated by
 * CFG_SENSOR_LINK_PTA, see core/pta/sub.mk) - the address has no meaning on
 * any other platform.
 */
#define SENSOR_UART_BASE	0x090c0000
/* QEMU's PL011 emulation ignores the programmed baud rate entirely (it
 * transports bytes as fast as the chardev backend allows), so the clock
 * value passed to pl011_init() is a don't-care - 1, matching this codebase's
 * own generic CONSOLE_UART_CLK_IN_HZ fallback for the same reason. */
#define SENSOR_UART_CLK_IN_HZ	1

/* Bounded busy-poll read timeout: ~2s, matching the granularity of the
 * mdelay() calls below. A missing/dead sensor_daemon must fail the caller
 * (TEE_ERROR_COMMUNICATION) rather than hang the TA forever. */
#define SENSOR_LINK_READ_TIMEOUT_MS	2000
#define SENSOR_LINK_POLL_STEP_MS	1

static struct pl011_data sensor_uart;
static bool sensor_uart_ready;

/*
 * Declarative, file-scope only: expands to a linker-collected array entry
 * the MMU/page-table setup scans at boot, so it must NOT be called from
 * inside a function - unlike pl011_init() below, which actually programs
 * the hardware and is safe to defer. Mirrors plat-vexpress/main.c's own
 * file-scope register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
 * ...) call for the console UART.
 */
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SENSOR_UART_BASE, PL011_REG_SIZE);

static void sensor_uart_ensure_init(void)
{
	if (sensor_uart_ready)
		return;

	pl011_init(&sensor_uart, SENSOR_UART_BASE, SENSOR_UART_CLK_IN_HZ, 0);
	sensor_uart_ready = true;
}

static void uart_write(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		sensor_uart.chip.ops->putc(&sensor_uart.chip, buf[i]);
	if (sensor_uart.chip.ops->flush)
		sensor_uart.chip.ops->flush(&sensor_uart.chip);
}

/* Reads exactly @len bytes into @buf, polling in SENSOR_LINK_POLL_STEP_MS
 * steps up to SENSOR_LINK_READ_TIMEOUT_MS total. Returns false on timeout. */
static bool uart_read(uint8_t *buf, size_t len)
{
	size_t got = 0;
	uint32_t waited_ms = 0;

	while (got < len) {
		if (sensor_uart.chip.ops->have_rx_data(&sensor_uart.chip)) {
			buf[got++] = (uint8_t)sensor_uart.chip.ops->getchar(
				&sensor_uart.chip);
			continue;
		}
		if (waited_ms >= SENSOR_LINK_READ_TIMEOUT_MS)
			return false;
		mdelay(SENSOR_LINK_POLL_STEP_MS);
		waited_ms += SENSOR_LINK_POLL_STEP_MS;
	}
	return true;
}

/* Writes one framed message: [1B type][2B length BE][payload]. */
static void write_frame(uint8_t type, const uint8_t *payload, uint16_t len)
{
	uint8_t hdr[SENSOR_LINK_FRAME_HDR_SIZE];

	hdr[0] = type;
	hdr[1] = (uint8_t)(len >> 8);
	hdr[2] = (uint8_t)(len & 0xff);
	uart_write(hdr, sizeof(hdr));
	if (len)
		uart_write(payload, len);
}

/*
 * Reads one framed message whose type must be @want_type. @payload must be
 * at least SENSOR_LINK_READING_MAX bytes (the largest payload this protocol
 * ever carries). Returns the payload length via *out_len, or false on
 * timeout / a frame whose type doesn't match / an oversized length field.
 */
static bool read_frame(uint8_t want_type, uint8_t *payload, size_t *out_len)
{
	uint8_t hdr[SENSOR_LINK_FRAME_HDR_SIZE];
	uint16_t len;

	if (!uart_read(hdr, sizeof(hdr)))
		return false;
	if (hdr[0] != want_type)
		return false;
	len = ((uint16_t)hdr[1] << 8) | hdr[2];
	if (len > SENSOR_LINK_READING_MAX)
		return false;
	if (len && !uart_read(payload, len))
		return false;
	*out_len = len;
	return true;
}

static TEE_Result sensor_link_challenge(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	size_t resp_len = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		DMSG(PTA_NAME" CHALLENGE: bad param types 0x%"PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (params[0].memref.size != SENSOR_LINK_CHALLENGE_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < SENSOR_LINK_HMAC_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	sensor_uart_ensure_init();

	write_frame(SENSOR_LINK_FRAME_CHALLENGE, params[0].memref.buffer,
		    SENSOR_LINK_CHALLENGE_SIZE);

	if (!read_frame(SENSOR_LINK_FRAME_CHALLENGE_RESPONSE,
			 params[1].memref.buffer, &resp_len)) {
		DMSG(PTA_NAME" CHALLENGE: no/bad response from sensor");
		return TEE_ERROR_COMMUNICATION;
	}
	if (resp_len != SENSOR_LINK_HMAC_SIZE)
		return TEE_ERROR_COMMUNICATION;

	params[1].memref.size = resp_len;
	return TEE_SUCCESS;
}

static TEE_Result sensor_link_read(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	size_t len = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		DMSG(PTA_NAME" READ: bad param types 0x%"PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (params[0].memref.size < SENSOR_LINK_READING_MAX)
		return TEE_ERROR_SHORT_BUFFER;

	sensor_uart_ensure_init();

	if (!read_frame(SENSOR_LINK_FRAME_READING, params[0].memref.buffer,
			 &len)) {
		DMSG(PTA_NAME" READ: no/bad reading from sensor");
		return TEE_ERROR_COMMUNICATION;
	}

	params[0].memref.size = len;
	return TEE_SUCCESS;
}

/*
 * Only the confidential_iot TA may open a session here - anything else
 * (including a raw Normal-World TEEC_OpenSession(), which reaches this same
 * open_session_entry_point per core/tee/entry_std.c's shared dispatch path)
 * is rejected. Stricter than core/pta/system.c's "any user TA" check: this
 * PTA is single-purpose, so it allowlists the one caller UUID it exists for.
 */
static TEE_Result open_session(uint32_t param_types __unused,
				TEE_Param params[TEE_NUM_PARAMS] __unused,
				void **sess_ctx __unused)
{
	struct ts_session *s = NULL;
	TEE_UUID allowed = SENSOR_LINK_ALLOWED_CALLER_UUID;

	s = ts_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;
	if (memcmp(&s->ctx->uuid, &allowed, sizeof(allowed)) != 0)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				  uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_SENSOR_LINK_CMD_CHALLENGE:
		return sensor_link_challenge(param_types, params);
	case PTA_SENSOR_LINK_CMD_READ:
		return sensor_link_read(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

pseudo_ta_register(.uuid = PTA_SENSOR_LINK_UUID, .name = PTA_NAME,
		    .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		    .open_session_entry_point = open_session,
		    .invoke_command_entry_point = invoke_command);
