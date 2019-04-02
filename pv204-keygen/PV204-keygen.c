/* PV204-keygen.c
   modified rsa-keygen.c as a part of PV204 Security
   Technologies course at the Faculty of Informatics of Masaryk University
   by Richard Kalinec on 8th of March, 2019.
   Subsequently merged with ecdsa-keygen.c created by Ondřej Zoder on
   March 9th, 2019.
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
//#include "sexp.h"
#include "nettle/yarrow.h"

//#include "io.h"

//#include "getopt.h"

// includes added for measuring time, not in rsa-keygen.c
#include <time.h>
#include <stdarg.h>

// includes added for seeding RNG
#include <sys/random.h>

// defined a prototype for our key generation functions
#include "PV204-keygen.h" 

// includes added for ECDSA keys generation
#include "nettle/ecc-curve.h"
#include "nettle/ecc.h"
#include "nettle/ecdsa.h"

//#define DEFAULT_KEYSIZE 2048 - we don't need this, as we specify key
// length as needed
#define ESIZE 30
#define OUTPUT_FILE_RSA "rsa-keys.csv"

#define ECDSA_KEYGEN_ROUNDS 1000000
#define OUTPUT_FILE_ECDSA "ecdsa-keys.csv"

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

/* generateKeys() function was carved out from the main() funtion to
   avoid repetitive code. It generates a given number of keys with a
   given length and writes information about them to a given, already
   open output file. Therefore its code is also based on rsa-keygen.c,
   but heavily modified to suit our needs.
*/
int
generate_rsa_keys(FILE *ofile, void *yarrow, int keylen, int numkeys, int counter)
{
  struct rsa_public_key pub;
  struct rsa_private_key priv;

  unsigned long long int gentime;
  for ( ; counter <= numkeys; counter++)
  {
    rsa_public_key_init(&pub);
    rsa_private_key_init(&priv);
    
    /* Measure the time before generating a key */
    cgt_time_start();

    if (!rsa_generate_keypair
        (&pub, &priv,
         yarrow, (nettle_random_func *) yarrow256_random,
         NULL, progress,
         keylen, ESIZE))
      {
        printf("Key generation failed.\n");
        return EXIT_FAILURE;
      }

    /* Measure the time after generating a key */
    gentime = cgt_time_end();
    
    /* Write information about the generated key pair and time it took
       to be generated to the output file */
    char *n = mpz_get_str(NULL, -16, pub.n);
    char *e = mpz_get_str(NULL, -16, pub.e);
    char *p = mpz_get_str(NULL, -16, priv.p);
    char *q = mpz_get_str(NULL, -16, priv.q);
    char *d = mpz_get_str(NULL, -16, priv.d);
    fprintf(ofile, "%u,%s,%s,%s,%s,%s,%llu\n", counter, n, e, p, q, d, gentime);
    
    rsa_public_key_clear(&pub);
    rsa_private_key_clear(&priv);
  }
  
  return EXIT_SUCCESS;
}

/* Generates 1000000 ECDSA NIST P-256 keys and writes information about
   them and how long each key took to generate to a single fixed CSV file.
*/
static int
gen_ecdsa_keys(void *yarrow_rng)
{
  const struct ecc_curve *ecc;
  struct ecc_point pub;
  struct ecc_scalar key;
  mpz_t x, y, z;
  unsigned counter;
  unsigned long long int elapsed_time;
  FILE *ecdsa_fp;

  ecdsa_fp = fopen(OUTPUT_FILE_ECDSA, "w");

  /* Initialize the ECC curve to NIST P-256 */
  ecc = nettle_get_secp_256r1();

  /* Initialize public and private key structures and integer variables */
  ecc_point_init(&pub, ecc);
  ecc_scalar_init(&key, ecc);
  mpz_inits(x, y, z, NULL);

  /* Iterate ECDSA_KEYGEN_ROUNDS times */
  for (counter = 1; counter <= ECDSA_KEYGEN_ROUNDS; counter++)
  {
    /* start the clock (using CPU time) */
    cgt_time_start();

    /* generate ECDSA keypair */
    ecdsa_generate_keypair(&pub, &key, yarrow_rng,
                           (nettle_random_func *)&yarrow256_random);
    /* Stop the clock and check its not equal to 0 */
    elapsed_time = cgt_time_end();

    /* Retrieve public and private keys from their structures */
    ecc_point_get(&pub, x, y);
    ecc_scalar_get(&key, z);

    /* Write all neccessary data into the output file */
    fprintf(ecdsa_fp, "%u;", counter);
    gmp_fprintf(ecdsa_fp, "04%064Zx%064Zx;%064Zx;", x, y, z);
    fprintf(ecdsa_fp, "%llu;\n", elapsed_time);
  }

  ecc_point_clear(&pub);
  ecc_scalar_clear(&key);
  mpz_clears(x, y, z, NULL);
  
  fclose(ecdsa_fp);

  return 0;
}

/* main() function was originally also based on that in rsa-keygen.c,
   but heavily modified to suit our goals - instead of taking arguments
   from the command line specifying the output files for private and pubic key
   and optionally a source file for RNG, the size of the modulus of the
   generated key and the size of the public exponent of the generated
   public key, our generator generates 1000000 512 b keys, 10000 1024 b
   keys and 10000 2048 keys, all with the default size of the public
   exponent; it does not write them to output files, but instead
   writes information about them to a fixed single CSV file. Additionally,
   it measures time each key took to be generated and writes this
   to the CSV file for each key as well. Most functionality was moved to
   the generate_rsa_keys() function called from main() function to avoid
   repetitive code. Later on, generation of ECDSA keys was added -
   gen_ecdsa_keys() function is called for this purpose. For seeding the RNG,
   the seed_rng() function is called before key generation itself. Similarly
   as in the case of RSA keys, information about them as well as generation
   times are written to a single fixed CSV file (separate from the
   one mentioned above).
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
  
  unsigned int counter = 1;
  int ret = 0;
  
  /* Open output file */
  FILE *rsa_of = fopen(OUTPUT_FILE_RSA, "w");
  
  /* Generate 1000000 512 b RSA keys */
  if ((ret = generate_rsa_keys(rsa_of, &yarrow, 512, 1000000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  /* Generate 10000 1024 b RSA keys */
  if ((ret = generate_rsa_keys(rsa_of, &yarrow, 1024, 10000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  /* Generate 10000 2048 b RSA keys */
  if ((ret = generate_rsa_keys(rsa_of, &yarrow, 2048, 10000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  /* Generate 1000000 ECDSA NIST P-256 keys */
  if (gen_ecdsa_keys(&yarrow))
  {
    printf("Error while generating keys\n");
    return 1;
  }
  
  fclose(rsa_of);
  
  return EXIT_SUCCESS;
}
