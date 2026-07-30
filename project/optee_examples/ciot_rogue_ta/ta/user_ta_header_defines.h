#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ciot_rogue_ta.h>

#define TA_UUID			TA_CIOT_ROGUE_UUID
#define TA_FLAGS		0
#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(16 * 1024)
#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Rogue TA signed with a non-project key (test fixture, must not load)"

#endif /* USER_TA_HEADER_DEFINES_H */
