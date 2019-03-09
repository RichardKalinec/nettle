/* PV204-rsa-keygen.c
   modified rsa-keygen.c as a part of PV204 Security
   Technologies course at the Faculty of Informatics of Masaryk University
   by Richard Kalinec on 8th of March, 2019.
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
   commented out. */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "rsa.h"
//#include "sexp.h"
#include "yarrow.h"

#include "io.h"

//#include "getopt.h"

// includes added for measuring time, not in rsa-keygen.c
#include <time.h>
#include <stdarg.h>

// defined a prototype for our generateKeys() function
#include "PV204-rsa-keygen.h" 

//#define DEFAULT_KEYSIZE 2048 - we don't need this, as we specify key
// length as needed
#define ESIZE 30

static void
progress(void *ctx, int c)
{
  (void) ctx;
  fputc(c, stderr);
}

// uint_arg() function omitted

/* All three following functions are taken from timing.h - die() and
   cgt_time_start() unmodified, cgt_time_end() modified to return 64-bit
   integer, a count of nanoseconds, instead of double, a count of seconds
   with the decimal part being nanoseconds.
*/
#if HAVE_CLOCK_GETTIME && defined CLOCK_PROCESS_CPUTIME_ID
struct timespec cgt_start;
static void NORETURN PRINTF_STYLE(1,2)
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

static void
cgt_time_start(void)
{
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cgt_start) < 0)
    die("clock_gettime failed: %s\n", strerror(errno));
}

static unsigned long long int
cgt_time_end(void)
{
  struct timespec end;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end) < 0)
    die("clock_gettime failed: %s\n", strerror(errno));

  return 1e9 * (end.tv_sec - cgt_start.tv_sec)
    + end.tv_nsec - cgt_start.tv_nsec;
}
#endif

/* generateKeys() function was carved out from the main() funtion to
   avoid repetitive code. It generates a given number of keys with a
   given length and writes information about them to a given, already
   open output file. Therefore its code is also based on rsa-keygen.c,
   but heavily modified to suit our needs.
*/
int
generateKeys(FILE *ofile, int keylen, int numkeys, int counter)
{
  struct yarrow256_ctx yarrow;
  struct rsa_public_key pub;
  struct rsa_private_key priv;

  /* NOTE: No sources */
  yarrow256_init(&yarrow, 0, NULL);

  /* Seed the generator */
  if (!simple_random(&yarrow, NULL))
    {
      werror("Initialization of randomness generator failed.\n");
      return EXIT_FAILURE;
    }

  unsigned long long int gentime;
  for ( ; counter <= numkeys; counter++)
  {
    rsa_public_key_init(&pub);
    rsa_private_key_init(&priv);
    
    /* Measure the time before generating a key */
    cgt_time_start();

    if (!rsa_generate_keypair
        (&pub, &priv,
         (void *) &yarrow, (nettle_random_func *) yarrow256_random,
         NULL, progress,
         keylen, ESIZE))
      {
        werror("Key generation failed.\n");
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

/* main() function is also based on that in rsa-keygen.c, but heavily
   modified to suit our goals - instead of taking arguments from the
   command line specifying the output files for private and pubic key
   and optionally a source file for RNG, the size of the modulus of the
   generated key and the size of the public exponent of the generated
   public key, our generator generates 1000000 512 b keys, 10000 1024 b
   keys and 10000 2048 keys, all with the default size of the public
   exponent; it does not write them to output files, but instead
   writes information about them to a fixed single CSV file. Additionally,
   it measures time each key took to be generated and writes this
   to the CSV file for each key as well. Most functionality was moved to
   the generateKeys() function called from main() function to avoid
   repetitive code.
*/
int
main(void)
{
  unsigned int counter = 1;
  int ret = 0;
  
  /* Open output file */
  FILE *ofile = fopen("rsaKeys.csv", "w");
  
  /* Generate 1000000 512 b keys */
  if ((ret = generateKeys(ofile, 512, 1000000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  /* Generate 10000 1024 b keys */
  if ((ret = generateKeys(ofile, 1024, 10000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  /* Generate 10000 2048 b keys */
  if ((ret = generateKeys(ofile, 2048, 10000, counter)) == EXIT_SUCCESS) { }
  else
  {
    return ret;
  }
  
  fclose(ofile);
  
  return EXIT_SUCCESS;
}
