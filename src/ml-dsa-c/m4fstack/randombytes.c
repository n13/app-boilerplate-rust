#include "randombytes.h"
#include <stdint.h>
#include <stddef.h>

/* Simple deterministic RNG for testing in Speculos.
 * NO static variables - uses the output buffer address as seed.
 * In production on real Ledger device, replace with cx_rng_no_throw().
 */
void randombytes(uint8_t *out, size_t outlen) {
    /* Use address of out as initial seed - different per call */
    uint32_t seed = (uint32_t)((uintptr_t)out & 0xFFFFFFFF);
    if (seed == 0) seed = 12345;
    
    for (size_t i = 0; i < outlen; i++) {
        /* xorshift32 */
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        out[i] = (uint8_t)(seed & 0xFF);
    }
}
