#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ciot_probe_ta.h>

#define TA_UUID			TA_CIOT_PROBE_UUID
/* Matches the confidential_iot TA's flags, so the UUID stays the only difference
 * between them - which is the whole point of this fixture. */
#define TA_FLAGS		0
/* Same as optee_examples/hello_world, the canonical minimal TA in this tree.
 * Deliberately not tuned down: this fixture's job is to be unremarkable, so that
 * when it fails to load the only interesting variable left is its UUID. */
#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(32 * 1024)
#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Confidential IoT storage-scope prober (test fixture)"

#endif /* USER_TA_HEADER_DEFINES_H */
