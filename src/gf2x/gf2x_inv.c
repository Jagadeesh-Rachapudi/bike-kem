/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The inversion algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "cleanup.h"
#include "gf2x.h"
#include "gf2x_internal.h"

// a = a^2 mod (x^r - 1)
_INLINE_ void gf2x_mod_sqr_in_place(IN OUT pad_r_t *a,
                                    OUT dbl_pad_r_t *secure_buffer,
                                    IN const gf2x_ctx *ctx)
{
  ctx->sqr(secure_buffer, a);
  ctx->red(a, secure_buffer);
}

// c = a^2^2^num_sqrs
_INLINE_ void repeated_squaring(OUT pad_r_t *c,
                                IN pad_r_t *    a,
                                IN const size_t num_sqrs,
                                OUT dbl_pad_r_t *sec_buf,
                                IN const gf2x_ctx *ctx)
{
  c->val = a->val;

  for(size_t i = 0; i < num_sqrs; i++) {
    gf2x_mod_sqr_in_place(c, sec_buf, ctx);
  }
}

// The gf2x_mod_inv function implements inversion in F_2[x]/(x^R - 1)
// based on [1](Algorithm 2).

// In every iteration, [1](Algorithm 2) performs two exponentiations:
// exponentiation 0 (exp0) and exponentiation 1 (exp1) of the form f^(2^k).
// These exponentiations are computed either by repeated squaring of f, k times,
// or by a single k-squaring of f. The method for a specific value of k
// is chosen based on the performance of squaring and k-squaring.
//
// Benchmarks on several platforms indicate that a good threshold
// for switching from repeated squaring to k-squaring is k = 64.
#define K_SQR_THR (64)

// k-squaring is computed by a permutation of bits of the input polynomial,
// as defined in [1](Observation 1). The required parameter for the permutation
// is l = (2^k)^-1 % R.
// Therefore, there are two sets of parameters for every exponentiation:
//   - exp0_k and exp1_k
//   - exp0_l and exp1_l

// Exponentiation 0 computes f^2^2^(i-1) for 0 < i < MAX_I.
// Exponentiation 1 computes f^2^((r-2) % 2^i) for 0 < i < MAX_I,
// only when the i-th bit of (r-2) is 1. Therefore, the value 0 in
// exp1_k[i] and exp1_l[i] means that exp1 is skipped in i-th iteration.

// To quickly generate all the required parameters in Sage:
//   r = DESIRED_R
//   max_i = floor(log(r-2, 2)) + 1
//   exp0_k = [2^i for i in range(max_i)]
//   exp0_l = [inverse_mod((2^k) % r, r) for k in exp0_k]
//   exp1_k = [(r-2)%(2^i) if ((r-2) & (1<<i)) else 0 for i in range(max_i)]
//   exp1_l = [inverse_mod((2^k) % r, r) if k != 0 else 0 for k in exp1_k]
//   print("#  define MAX_I (" + str(max_i) + ")")
//   print("#  define EXP0_K_VALS " + str(exp0_k)[1:-1])
//   print("#  define EXP0_L_VALS " + str(exp0_l)[1:-1])
//   print("#  define EXP1_K_VALS " + str(exp1_k)[1:-1])
//   print("#  define EXP1_L_VALS " + str(exp1_l)[1:-1])

#if (R_BITS == 12323)
// These parameters below are hard-coded for R=12323
bike_static_assert((R_BITS == 12323), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (14)
#  define EXP0_K_VALS \
     1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#  define EXP0_L_VALS \
     6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608, 10157, 8816
#  define EXP1_K_VALS 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129
#  define EXP1_L_VALS 0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717

#elif (R_BITS == 10499)

#  define MAX_I (14)
#  define EXP0_K_VALS 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#  define EXP0_L_VALS 5250, 2625, 3281, 3486, 4853, 2352, 9430, 8869, 653, 6449, 3062, 237, 3674, 7061
#  define EXP1_K_VALS 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 257, 0, 2305
#  define EXP1_L_VALS 0, 0, 0, 0, 0, 0, 0, 0, 5250, 0, 0, 5576, 0, 9137

#elif (R_BITS == 10627)

#  define MAX_I (14)
#  define EXP0_K_VALS 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#  define EXP0_L_VALS 5314, 2657, 3321, 8842, 8752, 8715, 56, 3136, 4521, 3720, 2046, 9705, 10551, 5776
#  define EXP1_K_VALS 0, 0, 0, 0, 0, 0, 0, 1, 129, 0, 0, 385, 0, 2433
#  define EXP1_L_VALS 0, 0, 0, 0, 0, 0, 0, 5314, 1568, 0, 0, 719, 0, 6583

#elif (R_BITS == 20233)

#  define MAX_I (15)
#  define EXP0_K_VALS 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#  define EXP0_L_VALS 10117, 15175, 8852, 15728, 1326, 18238, 14357, 9878, 11358, 18789, 1137, 18090, 19791, 13267, 6422
#  define EXP1_K_VALS 0, 1, 3, 0, 0, 0, 0, 0, 7, 263, 775, 1799, 0, 0, 3847
#  define EXP1_L_VALS 0, 10117, 17704, 0, 0, 0, 0, 0, 11223, 2934, 12234, 9987, 0, 0, 4373

#elif (R_BITS == 20107)

#  define MAX_I (15)
#  define EXP0_K_VALS 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#  define EXP0_L_VALS 10054, 5027, 16337, 17358, 16876, 3828, 15688, 3664, 13527, 6029, 15492, 4912, 19451, 8089, 3743
#  define EXP1_K_VALS 0, 0, 0, 1, 0, 0, 0, 9, 0, 137, 649, 1673, 0, 0, 3721
#  define EXP1_L_VALS 0, 0, 0, 10054, 0, 0, 0, 8679, 0, 10689, 1046, 18497, 0, 0, 13838

#elif (R_BITS == 20261)

#  define MAX_I (15)
#  define EXP0_K_VALS 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#  define EXP0_L_VALS 10131, 15196, 3799, 6569, 16092, 16884, 17447, 16806, 3296, 3720, 137, 18769, 17615, 11271, 19232
#  define EXP1_K_VALS 0, 1, 0, 0, 0, 3, 0, 0, 35, 291, 803, 1827, 0, 0, 3875
#  define EXP1_L_VALS 0, 10131, 0, 0, 0, 7598, 0, 0, 12241, 6685, 7953, 15728, 0, 0, 16323

#endif

// Inversion in F_2[x]/(x^R - 1), [1](Algorithm 2).
// c = a^{-1} mod x^r-1
void gf2x_mod_inv(OUT pad_r_t *c, IN const pad_r_t *a)
{
  // Initialize gf2x methods struct
  gf2x_ctx ctx;
  gf2x_ctx_init(&ctx);

  // Note that exp0/1_k/l are predefined constants that depend only on the value
  // of R. This value is public. Therefore, branches in this function, which
  // depends on R, are also "public". Code that releases these branches
  // (taken/not-taken) does not leak secret information.
  const size_t exp0_k[MAX_I] = {EXP0_K_VALS};
  const size_t exp0_l[MAX_I] = {EXP0_L_VALS};
  const size_t exp1_k[MAX_I] = {EXP1_K_VALS};
  const size_t exp1_l[MAX_I] = {EXP1_L_VALS};

  DEFER_CLEANUP(pad_r_t f = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t g = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t t = {0}, pad_r_cleanup);
  DEFER_CLEANUP(dbl_pad_r_t sec_buf = {0}, dbl_pad_r_cleanup);

  // Steps 2 and 3 in [1](Algorithm 2)
  f.val = a->val;
  t.val = a->val;

  for(size_t i = 1; i < MAX_I; i++) {
    // Step 5 in [1](Algorithm 2), exponentiation 0: g = f^2^2^(i-1)
    if(exp0_k[i - 1] <= K_SQR_THR) {
      repeated_squaring(&g, &f, exp0_k[i - 1], &sec_buf, &ctx);
    } else {
      ctx.k_sqr(&g, &f, exp0_l[i - 1]);
    }

    // Step 6, [1](Algorithm 2): f = f*g
    gf2x_mod_mul_with_ctx(&f, &g, &f, &ctx);

    if(exp1_k[i] != 0) {
      // Step 8, [1](Algorithm 2), exponentiation 1: g = f^2^((r-2) % 2^i)
      if(exp1_k[i] <= K_SQR_THR) {
        repeated_squaring(&g, &f, exp1_k[i], &sec_buf, &ctx);
      } else {
        ctx.k_sqr(&g, &f, exp1_l[i]);
      }

      // Step 9, [1](Algorithm 2): t = t*g;
      gf2x_mod_mul_with_ctx(&t, &g, &t, &ctx);
    }
  }

  // Step 10, [1](Algorithm 2): c = t^2
  gf2x_mod_sqr_in_place(&t, &sec_buf, &ctx);
  c->val = t.val;
}
