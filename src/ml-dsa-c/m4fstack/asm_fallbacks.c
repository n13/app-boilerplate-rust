/*
 * Pure C fallback implementations for ARM assembly functions.
 * These replace the .S assembly files when targeting non-ARM platforms
 * or when ARM assembly is not available/compatible.
 */

#include <stdint.h>
#include "params.h"
#include "reduce.h"
#include "ntt.h"           // Applies NAMESPACE to ntt, invntt_tomont
#include "pointwise_mont.h" // Applies NAMESPACE to asm_pointwise_*
#include "vector.h"        // Applies NAMESPACE to asm_reduce32, asm_caddq, etc.
#include "smallntt.h"      // Applies NAMESPACE to small_ntt_asm_769, etc.

/* ========================================
 * NTT functions (from pqcrystals reference)
 * ======================================== */

static const int32_t zetas[N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

void ntt(int32_t a[N]) {
  unsigned int len, start, j, k;
  int32_t zeta, t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = zetas[++k];
      for(j = start; j < start + len; ++j) {
        t = montgomery_reduce((int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

void invntt_tomont(int32_t a[N]) {
  unsigned int start, len, j, k;
  int32_t t, zeta;
  const int32_t f = 41978; // mont^2/256

  k = 256;
  for(len = 1; len < N; len <<= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = -zetas[--k];
      for(j = start; j < start + len; ++j) {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = montgomery_reduce((int64_t)zeta * a[j + len]);
      }
    }
  }

  for(j = 0; j < N; ++j) {
    a[j] = montgomery_reduce((int64_t)f * a[j]);
  }
}

/* ========================================
 * Pointwise Montgomery multiplication
 * ======================================== */

void asm_pointwise_montgomery(int32_t c[N], const int32_t a[N], const int32_t b[N]) {
  unsigned int i;
  for(i = 0; i < N; ++i)
    c[i] = montgomery_reduce((int64_t)a[i] * b[i]);
}

void asm_pointwise_acc_montgomery(int32_t c[N], const int32_t a[N], const int32_t b[N]) {
  unsigned int i;
  for(i = 0; i < N; ++i)
    c[i] += montgomery_reduce((int64_t)a[i] * b[i]);
}

/* ========================================
 * Vector operations
 * ======================================== */

void asm_reduce32(int32_t a[N]) {
  unsigned int i;
  for(i = 0; i < N; ++i)
    a[i] = reduce32(a[i]);
}

void small_asm_reduce32_central(int32_t a[N]) {
  unsigned int i;
  int32_t t;
  for(i = 0; i < N; ++i) {
    t = reduce32(a[i]);
    /* Center reduction: if t > Q/2, subtract Q */
    t -= (Q/2 + 1) & ~(((Q/2 - t) >> 31) - 1);
    t += (Q/2 + 1) & (((-Q/2 - 1 - t) >> 31) - 1);
    a[i] = t;
  }
}

void asm_caddq(int32_t a[N]) {
  unsigned int i;
  for(i = 0; i < N; ++i)
    a[i] = caddq(a[i]);
}

void asm_freeze(int32_t a[N]) {
  unsigned int i;
  for(i = 0; i < N; ++i)
    a[i] = freeze(a[i]);
}

/* ========================================
 * Rejection sampling
 * ======================================== */

unsigned int asm_rej_uniform(int32_t *a,
                             unsigned int len,
                             const unsigned char *buf,
                             unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < Q)
      a[ctr++] = t;
  }

  return ctr;
}

/* ========================================
 * Small NTT functions (mod 769) - for signing only
 * Pure C implementations for non-ARM platforms
 * ======================================== */

#define SMALL_Q 769
#define SMALL_QINV 5585134  /* -Q^(-1) mod 2^32 for Q = 769 */

/* Montgomery reduce for small Q = 769 */
static int16_t small_montgomery_reduce(int32_t a) {
  const int32_t qinv = SMALL_QINV;
  int32_t t;
  t = (int32_t)((int64_t)a * qinv);
  t = (a - (int64_t)t * SMALL_Q) >> 32;
  return (int16_t)t;
}

/* Small NTT for Q = 769 
 * Uses CT (Cooley-Tukey) butterfly with Montgomery reduction
 */
void small_ntt_asm_769(int16_t a[N], const int32_t *zetas) {
  unsigned int len, start, j, k;
  int32_t zeta;
  int16_t t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = zetas[k++];
      for(j = start; j < start + len; ++j) {
        t = small_montgomery_reduce((int32_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

/* Small inverse NTT for Q = 769
 * Uses GS (Gentleman-Sande) butterfly with Montgomery reduction
 */
void small_invntt_asm_769(int16_t a[N], const int32_t *zetas) {
  unsigned int start, len, j, k;
  int32_t zeta;
  int16_t t;
  /* f = 512^-1 * 2^32 mod 769, for Montgomery reduction after INTT */
  const int32_t f = 51193613;

  k = N;
  for(len = 1; len < N; len <<= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = zetas[--k];
      for(j = start; j < start + len; ++j) {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = small_montgomery_reduce((int32_t)zeta * a[j + len]);
      }
    }
  }

  /* Multiply by 2^64 / 256 = 2^56 mod Q, scaled by 2^32 for Montgomery */
  for(j = 0; j < N; ++j) {
    a[j] = small_montgomery_reduce((int32_t)f * a[j]);
  }
}

/* Small basemul for Q = 769
 * Pointwise multiplication in NTT domain
 */
void small_basemul_asm_769(int16_t *c, const int16_t *a, const int16_t *b, const int32_t *zetas) {
  unsigned int i;
  for(i = 0; i < N; ++i) {
    c[i] = small_montgomery_reduce((int32_t)a[i] * b[i]);
  }
  (void)zetas; /* zetas already applied in NTT, not needed for basemul */
}
