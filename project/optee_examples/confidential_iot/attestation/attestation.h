#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stddef.h>

int create_attestation_report(char *out, size_t out_size);
int verify_attestation_report(const char *report, size_t report_size);

#endif /* ATTESTATION_H */
