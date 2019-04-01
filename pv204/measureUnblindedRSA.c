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
#include "measureUnblindedRSA.h" 

#define DEFAULT_KEYSIZE 2048
#define ESIZE 30
#define NUM_MEASUREMENTS 10

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
measure_to_sexp(struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  struct nettle_buffer buffer;
  unsigned long long int gentime;
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    nettle_buffer_init(&buffer);

    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_keypair_to_sexp(&buffer, NULL, pub, priv))
    {
      printf("Formatting private key failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();

    nettle_buffer_clear(&buffer);
    
    fprintf(ofile, "%llu\n", gentime);
  }

  fclose(ofile);
}

void
measure_sign(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  struct sha256_ctx hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, data_len, data);
  
  mpz_t signature;
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_sha256_sign(priv, &hash_ctx, signature))
    {
      printf("Signing the data failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }

  fclose(ofile);
}

void
measure_sign_digest(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
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
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_sha256_sign_digest(priv, digest, signature))
    {
      printf("Signing the digest failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }

  fclose(ofile);
}

void
measure_compute_root(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  struct sha256_ctx hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, data_len, data);
  
  mpz_t signature;
  
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
  
    rsa_compute_root(priv, signature, signature);
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }

  fclose(ofile);
}

void
measure_decrypt(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len)
{
  /* Open output file */
  FILE *ofile = fopen(ofile_name, "w");
  
  unsigned long long int gentime;
  
  mpz_t ciphertext;
  if (!rsa_encrypt(pub, yarrow, (void*) getrandom, data_len, data, ciphertext))
  {
    printf("Encrypting the data before decryption failed.\n");
    exit(EXIT_FAILURE);
  }
  size_t data_length = DEFAULT_KEYSIZE / 8;
  uint8_t decrypted_data[DEFAULT_KEYSIZE / 8];
  
  // Perform NUM_MEASUREMENTS measurements of the function's execution time
  for (int i = 0; i < NUM_MEASUREMENTS; i++)
  {
    /* Measure the time before the function execution */
    cgt_time_start();
  
    if (!rsa_decrypt(priv, &data_length, decrypted_data, ciphertext))
    {
      printf("Decrypting the data failed.\n");
      exit(EXIT_FAILURE);
    }
  
    /* Measure the time after the function execution */
    gentime = cgt_time_end();
    
    fprintf(ofile, "%llu\n", gentime);
  }

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
  
  // Perform first round of measurements
  uint8_t data[DEFAULT_KEYSIZE / 8];
  for (int i = 0; i < DEFAULT_KEYSIZE / 8; i++)
  {
    data[i] = 0xaa;
  }
  printf("Executing measure_to_sexp() with half HW data and random exponent...\n");
  measure_to_sexp(&pub, &priv, "measureToSexpRR.txt");
  printf("Executing measure_sign() with half HW data and random exponent...\n");
  measure_sign(&priv, "measureSignRR.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_sign_digest() with half HW data and random exponent...\n");
  measure_sign_digest(&priv, "measureSignDigestRR.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_compute_root() with half HW data and random exponent...\n");
  measure_compute_root(&priv, "measureComputeRootRR.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_decrypt() with half HW data and random exponent...\n");
  measure_decrypt(&yarrow, &pub, &priv, "measureDecryptRR.txt", data, DEFAULT_KEYSIZE / 8);
  
  // Perform second round of measurements
  uint8_t data0[DEFAULT_KEYSIZE / 8];
  for (int i = 0; i < DEFAULT_KEYSIZE / 8; i++)
  {
    data0[i] = 0;
  }
  printf("Executing measure_to_sexp() with data consisting of zeroes and random exponent...\n");
  measure_to_sexp(&pub, &priv, "measureToSexpLR.txt");
  printf("Executing measure_sign() with data consisting of zeroes and random exponent...\n");
  measure_sign(&priv, "measureSignLR.txt", data0, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_sign_digest() with data consisting of zeroes and random exponent...\n");
  measure_sign_digest(&priv, "measureSignDigestLR.txt", data0, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_compute_root() with data consisting of zeroes and random exponent...\n");
  measure_compute_root(&priv, "measureComputeRootLR.txt", data0, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_decrypt() with data consisting of zeroes and random exponent...\n");
  measure_decrypt(&yarrow, &pub, &priv, "measureDecryptLR.txt", data0, DEFAULT_KEYSIZE / 8);
  
  // Perform third round of measurements
  uint8_t data1[DEFAULT_KEYSIZE / 8];
  for (int i = 0; i < DEFAULT_KEYSIZE / 8; i++)
  {
    data1[i] = 0xff;
  }
  printf("Executing measure_to_sexp() with data consisting of ones and random exponent...\n");
  measure_to_sexp(&pub, &priv, "measureToSexpHR.txt");
  printf("Executing measure_sign() with data consisting of ones and random exponent...\n");
  measure_sign(&priv, "measureSignHR.txt", data1, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_sign_digest() with data consisting of ones and random exponent...\n");
  measure_sign_digest(&priv, "measureSignDigestHR.txt", data1, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_compute_root() with data consisting of ones and random exponent...\n");
  measure_compute_root(&priv, "measureComputeRootHR.txt", data1, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_decrypt() with data consisting of ones and random exponent...\n");
  measure_decrypt(&yarrow, &pub, &priv, "measureDecryptHR.txt", data1, DEFAULT_KEYSIZE / 8);  
  
  rsa_public_key_clear(&pub);
  rsa_private_key_clear(&priv);
  
  size_t offset = 1;
  while(1)
  {
    // Make d, the private exponent with only MSB and LSB set to 1
    uint8_t expl[DEFAULT_KEYSIZE / 8 - offset];
    expl[0] = 0x80;
    expl[DEFAULT_KEYSIZE / 8 - offset - 1] = 1;
    for (size_t i = 1; i < DEFAULT_KEYSIZE / 8 - offset - 1; i++)
    {
      expl[i] = 0;
    }
    
    // Set this d to the private key
    nettle_mpz_init_set_str_256_u(priv.d, DEFAULT_KEYSIZE / 8 - offset, expl);
    
    // Compute e, the public exponent, an inverse of d mod phi(n) = (p - 1) * (q - 1)
    mpz_t pd;
    mpz_t qd;
    mpz_t phin;
    mpz_sub_ui(pd, priv.p, 1);
    mpz_sub_ui(qd, priv.q, 1);
    mpz_mul(phin, pd, qd);
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
  // Perform fourth round of measurements
  printf("Executing measure_to_sexp() with half HW data and low HW exponent...\n");
  measure_to_sexp(&pub, &priv, "measureToSexpRL.txt");
  printf("Executing measure_sign() with half HW data and low HW exponent...\n");
  measure_sign(&priv, "measureSignRL.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_sign_digest() with half HW data and low HW exponent...\n");
  measure_sign_digest(&priv, "measureSignDigestRL.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_compute_root() with half HW data and low HW exponent...\n");
  measure_compute_root(&priv, "measureComputeRootRL.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_decrypt() with half HW data and low HW exponent...\n");
  measure_decrypt(&yarrow, &pub, &priv, "measureDecryptRL.txt", data, DEFAULT_KEYSIZE / 8);
  
  offset = 1;
  while(1)
  {
    // Make d, the private exponent with all bits set to 1
    uint8_t expl[DEFAULT_KEYSIZE / 8 - offset];
    for (size_t i = 0; i < DEFAULT_KEYSIZE / 8 - offset; i++)
    {
      expl[i] = 0xff;
    }
    
    // Set this d to the private key
    nettle_mpz_init_set_str_256_u(priv.d, DEFAULT_KEYSIZE / 8 - offset, expl);
    
    // Compute e, the public exponent, an inverse of d mod phi(n) = (p - 1) * (q - 1)
    mpz_t pd;
    mpz_t qd;
    mpz_t phin;
    mpz_sub_ui(pd, priv.p, 1);
    mpz_sub_ui(qd, priv.q, 1);
    mpz_mul(phin, pd, qd);
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
  // Perform fifth round of measurements
  printf("Executing measure_to_sexp() with half HW data and high HW exponent...\n");
  measure_to_sexp(&pub, &priv, "measureToSexpRH.txt");
  printf("Executing measure_sign() with half HW data and high HW exponent...\n");
  measure_sign(&priv, "measureSignRH.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_sign_digest() with half HW data and high HW exponent...\n");
  measure_sign_digest(&priv, "measureSignDigestRH.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_compute_root() with half HW data and high HW exponent...\n");
  measure_compute_root(&priv, "measureComputeRootRH.txt", data, DEFAULT_KEYSIZE / 8);
  printf("Executing measure_decrypt() with half HW data and high HW exponent...\n");
  measure_decrypt(&yarrow, &pub, &priv, "measureDecryptRH.txt", data, DEFAULT_KEYSIZE / 8);
  
  return EXIT_SUCCESS;
}