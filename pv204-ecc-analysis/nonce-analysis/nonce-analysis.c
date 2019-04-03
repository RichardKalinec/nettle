#include "nettle/ecdsa.h"
#include "nettle/ecc-curve.h"
#include "nettle/yarrow.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#define SAMPLE_SIZE 1000000

struct timespec cgt_start;

static int cgt_time_start(void)
{
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cgt_start) < 0)
  {
    printf("clock_gettime failed\n");
    return 0;
  }
  return 1;
}

static unsigned cgt_time_end(void)
{
  struct timespec end;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end) < 0)
  {
    printf("clock_gettime failed\n");
    return 0;
  }

  return end.tv_nsec - cgt_start.tv_nsec;
}

static int seed_rng(struct yarrow256_ctx *ctx)
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

int main(void)
{
    struct ecc_point pub;
    struct ecc_scalar key;
    struct dsa_signature signature;
    const struct ecc_curve *ecc;
    struct yarrow256_ctx yarrow_rng;
    struct ecc_scalar rand_nonce_k;
    mpz_t rand_nonce;
    unsigned elapsed_time, i;
    FILE *ecdsa_sign_under;
    uint8_t data[32];

    yarrow256_init(&yarrow_rng, 0, NULL);
    if (seed_rng(&yarrow_rng))
    {
        printf("Initialization of randomness generator failed.\n");
        return 1;
    }
    dsa_signature_init(&signature);
    ecc = nettle_get_secp_256r1();
    ecc_point_init(&pub, ecc);
    ecc_scalar_init(&key, ecc);
    ecc_scalar_init(&rand_nonce_k, ecc);
    mpz_init(rand_nonce);
    ecdsa_sign_under = fopen("ecdsa_sign_under.csv", "w");

    ecc_scalar_random(&rand_nonce_k, &yarrow_rng, (nettle_random_func *)&yarrow256_random);
    ecc_scalar_get(&rand_nonce_k, rand_nonce);
    mp_limb_t *k = malloc(1000);
    k = mpz_limbs_read(&(rand_nonce[0]));
    mp_limb_t *rp = mpz_limbs_write (signature.r, 32);
    mp_limb_t *sp = mpz_limbs_write (signature.s, 32);

    for (i = 0; i < SAMPLE_SIZE; i++)
    {
        ecdsa_generate_keypair(&pub, &key, &yarrow_rng, (nettle_random_func *)&yarrow256_random);
        ecc_scalar_random(&rand_nonce_k, &yarrow_rng, (nettle_random_func *)&yarrow256_random);
        ecc_scalar_get(&rand_nonce_k, rand_nonce);
        k = mpz_limbs_read(&(rand_nonce[0]));
        yarrow256_random(&yarrow_rng, 32, data);
        
        assert(cgt_time_start());
        ecc_ecdsa_sign (ecc, key.p, k, 32, data, rp, sp, k + 32);
        elapsed_time = cgt_time_end();
        ecc_scalar_get(&rand_nonce_k, rand_nonce);
        gmp_fprintf(ecdsa_sign_under, "%064Zx;", rand_nonce);
        fprintf(ecdsa_sign_under, "%u\n", elapsed_time);
    }
    
    //mpz_clear(rand_nonce);
    ecc_point_clear(&pub);
    ecc_scalar_clear(&key);
    ecc_scalar_clear(&rand_nonce_k);
    dsa_signature_clear(&signature);
    free(k);
    fclose(ecdsa_sign_under);
}