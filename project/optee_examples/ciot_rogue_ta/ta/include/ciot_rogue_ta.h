#ifndef CIOT_ROGUE_TA_H
#define CIOT_ROGUE_TA_H

/*
 * Rogue TA - test fixture, must never load. See rogue_ta.c.
 *
 * UUID ...0003, distinct from the real TA's ...0001 purely so the built .ta
 * lands in /lib/optee_armtz under its own filename and can never collide with,
 * or overwrite, the genuine one at install time. The mimicry test copies this
 * file over the genuine UUID's path at runtime instead - in RAM, on an
 * initramfs rootfs, with a backup and a restore.
 */
#define TA_CIOT_ROGUE_UUID \
	{ 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x03 } }

#endif /* CIOT_ROGUE_TA_H */
