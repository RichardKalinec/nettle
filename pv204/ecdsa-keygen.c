#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "nettle/ecc-curve.h"
#include "nettle/ecc.h"
#include "nettle/ecdsa.h"
#include "nettle/yarrow.h"

#include "gmp.h"

#define ECDSA_KEYGEN_ROUNDS 1000
#define OUTPUT_FILE "ecdsa-keys"

struct timespec cgt_start;

static int
cgt_time_start(void)
{
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cgt_start) < 0)
  {
    printf("clock_gettime failed\n");
    return 0;
  }
  return 1;
}

static unsigned long long int
cgt_time_end(void)
{
  struct timespec end;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end) < 0)
  {
    printf("clock_gettime failed\n");
    return 0;
  }

  return end.tv_nsec - cgt_start.tv_nsec;
}

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

  ecdsa_fp = fopen(OUTPUT_FILE, "w");

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
    if (!cgt_time_start())
      return 1;
    /* generate ECDSA keypair */
    ecdsa_generate_keypair(&pub, &key, yarrow_rng,
                           (nettle_random_func *)&yarrow256_random);
    /* Stop the clock and check its not equal to 0 */
    elapsed_time = cgt_time_end();
    if (!elapsed_time)
      return 1;

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

  return 0;
}

int main(void)
{
  struct yarrow256_ctx yarrow;

  yarrow256_init(&yarrow, 0, NULL);

  /* Seed the Yarrow random number generator */
  if (seed_rng(&yarrow))
  {
    printf("Initialization of randomness generator failed.\n");
    return 1;
  }

  if (gen_ecdsa_keys(&yarrow))
  {
    printf("Error while generating keys\n");
    return 1;
  }

  return 0;
}
