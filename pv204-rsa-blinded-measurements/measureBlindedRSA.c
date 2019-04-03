/* measureBlindedRSA.c
   Based on measureUnblindedRSA.c created by Filip Gontko with suitable
   adjustments. Made as a part of PV204 Security Technologies course at
   the Faculty of Informatics of Masaryk University by Richard Kalinec
   on 3rd of April, 2019.
*/
/* measureUnblindedRSA.c
   Helper functions, includes and RSA key generation function based on
   PV204-keygen.c with suitable adjustments. Made as a part of PV204
   Security Technologies course at the Faculty of Informatics of Masaryk
   University by Richard Kalinec on 30th of March, 2019.
*/
/* rsa-keygen.c
   Copyright (C) 2002 Niels Möller
   This file is part of GNU Nettle.
   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:
     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.
   or
     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.
   or both in parallel, as here.
   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

/* Includes are mostly the same as in rsa-keygen.c, those omitted are
   commented out. Nettle includes are modified to use installed nettle
   header files. */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nettle/buffer.h"
#include "nettle/rsa.h"
#include "nettle/sexp.h"
#include "nettle/yarrow.h"

//#include "io.h"

//#include "getopt.h"

// includes added for measuring time, not in rsa-keygen.c
#include <time.h>
#include <stdarg.h>

// includes added for seeding RNG
#include <sys/random.h>

// includes added for SHA2 - needed for signing
#include "nettle/sha2.h"

// needed for pkcs1_rsa_sha256_encode() in measure_compute_root()
#include "nettle/pkcs1.h"

// defined a prototype for our key generation functions
#include "measureBlindedRSA.h" 

#define DEFAULT_KEYSIZE 2048
#define DATA_LEN (DEFAULT_KEYSIZE / 16)
#define ESIZE 30
#define NUM_MEASUREMENTS 100000

static void
progress(void *ctx, int c)
{
  (void) ctx;
  fputc(c, stderr);
}

// uint_arg() function omitted

/* The two ollowing functions are taken from timing.h - die() function was
   replaced by simpler code with the same functionality and cgt_time_end()
   was modified to return 64-bit integer, a count of nanoseconds, instead
   of double, a count of seconds with the decimal part being nanoseconds.
*/
struct timespec cgt_start;

static void
cgt_time_start(void)
{
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cgt_start) < 0)
  {
    printf("clock_gettime failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static unsigned long long int
cgt_time_end(void)
{
  struct timespec end;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end) < 0)
  {
    printf("clock_gettime failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return 1e9 * (end.tv_sec - cgt_start.tv_sec)
    + end.tv_nsec - cgt_start.tv_nsec;
}

/* seed_rng() seeds the given instance of Yarrow RNG */
static int
seed_rng(struct yarrow256_ctx *ctx)
{
  uint8_t buffer[YARROW256_SEED_FILE_SIZE + 1];

  if (getrandom(buffer, YARROW256_SEED_FILE_SIZE, 0) !=
      YARROW256_SEED_FILE_SIZE)
  {
    printf("Generation of a random seed failed\n");
    return 1;
  }

  buffer[YARROW256_SEED_FILE_SIZE] = '\0';
  yarrow256_seed(ctx, YARROW256_SEED_FILE_SIZE, buffer);

  return 0;
}

/* Based on generate_rsa_keys() from PV204-keygen.c, but generates only one
   RSA keypair of the default length and stores it into the arguments supplied
   to the function. It does not measure key generation time.
*/
int
generate_rsa_key(struct rsa_public_key* pub, struct rsa_private_key* priv, void *yarrow)
{
  rsa_public_key_init(pub);
  rsa_private_key_init(priv);
  
  if (!rsa_generate_keypair
      (pub, priv,
       yarrow, (nettle_random_func *) yarrow256_random,
       NULL, progress,
       DEFAULT_KEYSIZE, ESIZE))
    {
      printf("Key generation failed.\n");
      return EXIT_FAILURE;
    }
  
  return EXIT_SUCCESS;
}

void
measure_from_sexp(struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  // Prepare the keypair in the sexp form
  struct nettle_buffer buffer;
  nettle_buffer_init(&buffer);
  if (!rsa_keypair_to_sexp(&buffer, NULL, pub, priv))
  {
    printf("Formatting private key failed.\n");
    exit(EXIT_FAILURE);
  }
  
  struct rsa_public_key pubn;
  struct rsa_private_key privn;
  rsa_public_key_init(&pubn);
  rsa_private_key_init(&privn);
  
  unsigned long long int gentime;
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    rsa_keypair_from_sexp(&pubn, &privn, DEFAULT_KEYSIZE, buffer.size, buffer.contents);
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();

    fprintf(ofile, "%llu\n", gentime);
  }

  rsa_public_key_clear(&pubn);
  rsa_private_key_clear(&privn);
  nettle_buffer_clear(&buffer);
    
  fclose(ofile);
}

void
measure_sign_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  struct sha256_ctx hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, data_len, data);
  
  mpz_t signature;
  mpz_init(signature);
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_sha256_sign_tr(pub, priv, yarrow, (nettle_random_func *) yarrow256_random, &hash_ctx, signature))
    {
      printf("Signing the data failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }
  
  mpz_clear(signature);

  fclose(ofile);
}

void
measure_sign_digest_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  uint8_t digest[SHA256_DIGEST_SIZE];
  struct sha256_ctx hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, data_len, data);
  sha256_digest(&hash_ctx, SHA256_DIGEST_SIZE, digest);
  
  mpz_t signature;
  mpz_init(signature);
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_sha256_sign_digest_tr(pub, priv, yarrow, (nettle_random_func *) yarrow256_random, digest, signature))
    {
      printf("Signing the digest failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }
  
  mpz_clear(signature);

  fclose(ofile);
}

void
measure_compute_root_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  struct sha256_ctx hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, data_len, data);
  
  mpz_t signature;
  mpz_init(signature);
  
  if (!pkcs1_rsa_sha256_encode(signature, priv->size, &hash_ctx))
  {
    printf("Encoding the data before computing root failed.\n");
    exit(EXIT_FAILURE);
  }
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    rsa_compute_root_tr(pub, priv, yarrow, (nettle_random_func *) yarrow256_random, signature, signature);
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }
  
  mpz_clear(signature);

  fclose(ofile);
}

void
measure_decrypt_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  mpz_t ciphertext;
  mpz_init(ciphertext);
  if (!rsa_encrypt(pub, yarrow, (nettle_random_func *) yarrow256_random, data_len, data, ciphertext))
  {
    printf("Encrypting the data before decryption failed.\n");
    exit(EXIT_FAILURE);
  }
  size_t data_length = DATA_LEN;
  uint8_t decrypted_data[DATA_LEN];
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_decrypt_tr(pub, priv, yarrow, (nettle_random_func *) yarrow256_random, &data_length, decrypted_data, ciphertext))
    {
      printf("Decrypting the data failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }
  
  mpz_clear(ciphertext);

  fclose(ofile);
}

/* At the beginning, the main() function initializes the Yarrow RNG, generates
   a random RSA keypair, which is used for the first three rounds of
   measurements. The fourth round of measurements is done with a specially
   crafted RSA keypair such that private exponent in the private key has low
   Hamming weight, and the fifth round of measurements is done with and RSA
   keypair with a private exponent in the private key with high HW. The first,
   fourth and fifth round of measurements use data consisting half of ones,
   half of zeroes, while the second round of measurements uses data consisting
   only of zeroes, and the third round of measurements uses data consisting
   only of ones. The measurements themselves measure the time of executions of
   functions rsa_keypair_to_sexp(), rsa_sha256_sign(), rsa_sha256_sign_digest(),
   rsa_decrypt(), and rsa_compute_root() in the aforementioned scenarios, with
   1 million repetitions per function in a particular scenario.
*/
int
main(void)
{
  struct yarrow256_ctx yarrow;
  
  /* NOTE: No sources */
  yarrow256_init(&yarrow, 0, NULL);

  /* Seed the Yarrrow RNG */
  if (seed_rng(&yarrow))
  {
    printf("Initialization of randomness generator failed.\n");
    return EXIT_FAILURE;
  }
  
  struct rsa_public_key pub;
  struct rsa_private_key priv;

  if (generate_rsa_key(&pub, &priv, &yarrow) == EXIT_FAILURE)
  {
    printf("RSA keypair generation failed.\n");
    return EXIT_FAILURE;
  }
  
  printf("First round of measurements:\n");
  uint8_t data[DATA_LEN];
  for (int i = 0; i < DATA_LEN; i++)
  {
    data[i] = 0xaa;
  }
  printf("Executing measure_from_sexp() with half HW data and random exponent...\n");
  measure_from_sexp(&pub, &priv, "measureFromSexpRR.txt");
  printf("Executing measure_sign_tr() with half HW data and random exponent...\n");
  measure_sign_tr(&yarrow, &pub, &priv, "measureSignTrRR.txt", data, DATA_LEN);
  printf("Executing measure_sign_digest_tr() with half HW data and random exponent...\n");
  measure_sign_digest_tr(&yarrow, &pub, &priv, "measureSignDigestTrRR.txt", data, DATA_LEN);
  printf("Executing measure_compute_root_tr() with half HW data and random exponent...\n");
  measure_compute_root_tr(&yarrow, &pub, &priv, "measureComputeRootTrRR.txt", data, DATA_LEN);
  printf("Executing measure_decrypt_tr() with half HW data and random exponent...\n");
  measure_decrypt_tr(&yarrow, &pub, &priv, "measureDecryptTrRR.txt", data, DATA_LEN);
  
  printf("Second round of measurements:\n");
  uint8_t data0[DATA_LEN];
  for (int i = 0; i < DATA_LEN; i++)
  {
    data0[i] = 0;
  }
  printf("Executing measure_from_sexp() with data consisting of zeroes and random exponent...\n");
  measure_from_sexp(&pub, &priv, "measureFromSexpLR.txt");
  printf("Executing measure_sign_tr() with data consisting of zeroes and random exponent...\n");
  measure_sign_tr(&yarrow, &pub, &priv, "measureSignTrLR.txt", data0, DATA_LEN);
  printf("Executing measure_sign_digest_tr() with data consisting of zeroes and random exponent...\n");
  measure_sign_digest_tr(&yarrow, &pub, &priv, "measureSignDigestTrLR.txt", data0, DATA_LEN);
  printf("Executing measure_compute_root_tr() with data consisting of zeroes and random exponent...\n");
  measure_compute_root_tr(&yarrow, &pub, &priv, "measureComputeRootTrLR.txt", data0, DATA_LEN);
  printf("Executing measure_decrypt_tr() with data consisting of zeroes and random exponent...\n");
  measure_decrypt_tr(&yarrow, &pub, &priv, "measureDecryptTrLR.txt", data0, DATA_LEN);
  
  printf("Third round of measurements:\n");
  uint8_t data1[DATA_LEN];
  for (int i = 0; i < DATA_LEN; i++)
  {
    data1[i] = 0xff;
  }
  printf("Executing measure_from_sexp() with data consisting of ones and random exponent...\n");
  measure_from_sexp(&pub, &priv, "measureFromSexpHR.txt");
  printf("Executing measure_sign_tr() with data consisting of ones and random exponent...\n");
  measure_sign_tr(&yarrow, &pub, &priv, "measureSignTrHR.txt", data1, DATA_LEN);
  printf("Executing measure_sign_digest_tr() with data consisting of ones and random exponent...\n");
  measure_sign_digest_tr(&yarrow, &pub, &priv, "measureSignDigestTrHR.txt", data1, DATA_LEN);
  printf("Executing measure_compute_root_tr() with data consisting of ones and random exponent...\n");
  measure_compute_root_tr(&yarrow, &pub, &priv, "measureComputeRootTrHR.txt", data1, DATA_LEN);
  printf("Executing measure_decrypt_tr() with data consisting of ones and random exponent...\n");
  measure_decrypt_tr(&yarrow, &pub, &priv, "measureDecryptTrHR.txt", data1, DATA_LEN);
  
  // Compute phi(n) for use for computation of inversion of d
  mpz_t pd;
  mpz_t qd;
  mpz_t phin;
  mpz_init(pd);
  mpz_init(qd);
  mpz_init(phin);
  mpz_sub_ui(pd, priv.p, 1);
  mpz_sub_ui(qd, priv.q, 1);
  mpz_mul(phin, pd, qd);
  
  printf("Preparing keys with low HW exponent...\n");
  size_t offset = 1;
  while(offset < 2048)
  {
    // Make d, the private exponent with only MSB and LSB set to 1
    uint8_t expl[DEFAULT_KEYSIZE / 8 - (offset / 8)];
    if((DEFAULT_KEYSIZE / 8 - (offset / 8)) > 1)
    {
      switch(offset % 8)
      {
        case 0: expl[0] = 0x80;
                break;
        case 1: expl[0] = 0x40;
                break;
        case 2: expl[0] = 0x20;
                break;
        case 3: expl[0] = 0x10;
                break;
        case 4: expl[0] = 0x8;
                break;
        case 5: expl[0] = 0x4;
                break;
        case 6: expl[0] = 0x2;
                break;
        case 7: expl[0] = 0x1;
                break;
      }
      expl[DEFAULT_KEYSIZE / 8 - (offset / 8) - 1] = 1;
    }
    else
    {
      switch(offset % 8)
      {
        case 0: expl[0] = 0x81;
                break;
        case 1: expl[0] = 0x41;
                break;
        case 2: expl[0] = 0x21;
                break;
        case 3: expl[0] = 0x11;
                break;
        case 4: expl[0] = 0x9;
                break;
        case 5: expl[0] = 0x5;
                break;
        case 6: expl[0] = 0x3;
                break;
        case 7: expl[0] = 0x1;
                break;
      }
    }
    for (size_t i = 1; i < DEFAULT_KEYSIZE / 8 - (offset / 8) - 1; i++)
    {
      expl[i] = 0;
    }
    
    // Set this d to the private key
    nettle_mpz_set_str_256_u(priv.d, DEFAULT_KEYSIZE / 8 - offset, expl);
    
    // Compute e, the public exponent, an inverse of d mod phi(n) = (p - 1) * (q - 1)
    if(mpz_invert(pub.e, priv.d, phin) == 0)
    {
      // Inversion of d mod phi(n) does not exist, retry for a higher offset
      offset++;
      continue;
    }
    else
    {
      // Inversion exists, it is already set in the public key; now calculate
      // new values of a and b
      mpz_mod(priv.a, priv.d, pd);
      mpz_mod(priv.b, priv.d, qd);
      break;
    }
  }
  if (offset == 2048)
  {
    printf("Did not find an inversion for d!\n");
    return EXIT_FAILURE;
  }
  printf("Fourth round of measurements:\n");
  printf("Executing measure_from_sexp() with half HW data and low HW exponent...\n");
  measure_from_sexp(&pub, &priv, "measureFromSexpRL.txt");
  printf("Executing measure_sign_tr() with half HW data and low HW exponent...\n");
  measure_sign_tr(&yarrow, &pub, &priv, "measureSignTrRL.txt", data, DATA_LEN);
  printf("Executing measure_sign_digest_tr() with half HW data and low HW exponent...\n");
  measure_sign_digest_tr(&yarrow, &pub, &priv, "measureSignDigestTrRL.txt", data, DATA_LEN);
  printf("Executing measure_compute_root_tr() with half HW data and low HW exponent...\n");
  measure_compute_root_tr(&yarrow, &pub, &priv, "measureComputeRootTrRL.txt", data, DATA_LEN);
  printf("Executing measure_decrypt_tr() with half HW data and low HW exponent...\n");
  measure_decrypt_tr(&yarrow, &pub, &priv, "measureDecryptTrRL.txt", data, DATA_LEN);
  
  printf("Preparing keys with high HW exponent...\n");
  offset = 0;
  while(offset < 2048)
  {
    // Make d, the private exponent with all bits set to 1
    uint8_t expl[DEFAULT_KEYSIZE / 8 - (offset / 8)];
    switch(offset % 8)
    {
      case 0: expl[0] = 0xff;
              break;
      case 1: expl[0] = 0x7f;
              break;
      case 2: expl[0] = 0x3f;
              break;
      case 3: expl[0] = 0x1f;
              break;
      case 4: expl[0] = 0xf;
              break;
      case 5: expl[0] = 0x7;
              break;
      case 6: expl[0] = 0x3;
              break;
      case 7: expl[0] = 0x1;
              break;
    }
    for (size_t i = 1; i < DEFAULT_KEYSIZE / 8 - offset; i++)
    {
      expl[i] = 0xff;
    }
    
    // Set this d to the private key
    nettle_mpz_set_str_256_u(priv.d, DEFAULT_KEYSIZE / 8 - offset, expl);
    
    // Compute e, the public exponent, an inverse of d mod phi(n) = (p - 1) * (q - 1)
    if(mpz_invert(pub.e, priv.d, phin) == 0)
    {
      // Inversion of d mod phi(n) does not exist, retry for a higher offset
      offset++;
      continue;
    }
    else
    {
      // Inversion exists, it is already set in the public key; now calculate
      // new values of a and b
      mpz_mod(priv.a, priv.d, pd);
      mpz_mod(priv.b, priv.d, qd);
      break;
    }
  }
  if (offset == 2048)
  {
    printf("Did not find an inversion for d!\n");
    return EXIT_FAILURE;
  }
  printf("Fifth round of measurements:\n");
  printf("Executing measure_from_sexp() with half HW data and high HW exponent...\n");
  measure_from_sexp(&pub, &priv, "measureFromSexpRH.txt");
  printf("Executing measure_sign_tr() with half HW data and high HW exponent...\n");
  measure_sign_tr(&yarrow, &pub, &priv, "measureSignTrRH.txt", data, DATA_LEN);
  printf("Executing measure_sign_digest_tr() with half HW data and high HW exponent...\n");
  measure_sign_digest_tr(&yarrow, &pub, &priv, "measureSignDigestTrRH.txt", data, DATA_LEN);
  printf("Executing measure_compute_root_tr() with half HW data and high HW exponent...\n");
  measure_compute_root_tr(&yarrow, &pub, &priv, "measureComputeRootTrRH.txt", data, DATA_LEN);
  printf("Executing measure_decrypt_tr() with half HW data and high HW exponent...\n");
  measure_decrypt_tr(&yarrow, &pub, &priv, "measureDecryptTrRH.txt", data, DATA_LEN);  
  
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  mpz_clear(pd);
  mpz_clear(qd);
  mpz_clear(phin);
  
  return EXIT_SUCCESS;
}