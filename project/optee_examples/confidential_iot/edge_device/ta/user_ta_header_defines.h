#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <confidential_iot_ta.h>

#define TA_UUID			TA_CONFIDENTIAL_IOT_UUID
#define TA_FLAGS		0
/* 4 KB, not 2: CMD 3 now nests the TA-identity signing path (a 160-byte sealed
 * blob, TA-local copies of the nonce and both 65-byte public points, a digest,
 * and a TEE_Attribute array) on top of its existing frame. A TA stack overflow
 * surfaces as an opaque data abort rather than an error return, so leave the
 * headroom - and raise this before debugging any unexplained TA panic. */
#define TA_STACK_SIZE		(4 * 1024)
#define TA_DATA_SIZE		(32 * 1024)
#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Confidential IoT Trusted Application stubs"

#endif /* USER_TA_HEADER_DEFINES_H */
