#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

// Generate random bytes using Ledger's hardware RNG
void randombytes(uint8_t *out, size_t outlen);

#endif
