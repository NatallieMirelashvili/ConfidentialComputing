#ifndef SECURE_ELEMENT_H
#define SECURE_ELEMENT_H

#include <stddef.h>
#include <stdint.h>

size_t get_identity(char *out, size_t out_size);
int respond_to_challenge(const uint8_t *challenge, size_t challenge_size,
			 uint8_t *response, size_t *response_size);

#endif /* SECURE_ELEMENT_H */
