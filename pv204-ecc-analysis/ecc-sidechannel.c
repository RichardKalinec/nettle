#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "nettle/dsa.h"
#include "nettle/ecc-curve.h"
#include "nettle/ecc.h"
#include "nettle/ecdsa.h"
#include "nettle/sha2.h"
#include "nettle/yarrow.h"

#include "gmp.h"

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

void yarrow256_ones(struct yarrow256_ctx *ctx, size_t length, uint8_t *dst)
{
  unsigned vals[] = {254, 253, 251, 247, 239, 223, 191, 127};
  memset(dst, 255, length);
  memset(dst + (rand() % length), vals[rand() % 8], 1);
}

void yarrow256_zeros(struct yarrow256_ctx *ctx, size_t length, uint8_t *dst)
{
  unsigned vals[] = {1, 2, 4, 8, 16, 32, 64, 128};
  memset(dst, 0, length);
  memset(dst + (rand() % length), vals[rand() % 8], 1);
  memset(dst + length - 1, 128, 1);
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

void measure_get(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                 nettle_random_func *random_func)
{
  unsigned int elapsed_time, i;
  mpz_t z;
  mpz_init(z);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    ecc_scalar_random(key, yarrow_rng, random_func);
    assert(cgt_time_start());
    ecc_scalar_get(key, z);
    elapsed_time = cgt_time_end();
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  mpz_clear(z);
}

void scalar_get_analysis(void *yarrow_rng, const struct ecc_curve *ecc)
{
  struct ecc_scalar key;
  FILE *randsc_scget_fp;
  FILE *lhwsc_scget_fp;
  FILE *hhwsc_scget_fp;

  ecc_scalar_init(&key, ecc);
  randsc_scget_fp = fopen("randsc_scget.csv", "w");
  lhwsc_scget_fp = fopen("lhwsc_scget.csv", "w");
  hhwsc_scget_fp = fopen("hhwsc_scget.csv", "w");

  measure_get(randsc_scget_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_random);
  measure_get(lhwsc_scget_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_zeros);
  measure_get(hhwsc_scget_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_ones);

  fclose(randsc_scget_fp);
  fclose(lhwsc_scget_fp);
  fclose(hhwsc_scget_fp);
  ecc_scalar_clear(&key);
}

void measure_clear(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                   nettle_random_func *random_func,
                   const struct ecc_curve *ecc)
{
  unsigned int elapsed_time, i;
  mpz_t z;
  mpz_init(z);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    ecc_scalar_init(key, ecc);
    ecc_scalar_random(key, yarrow_rng, random_func);
    ecc_scalar_get(key, z);
    assert(cgt_time_start());
    ecc_scalar_clear(key);
    elapsed_time = cgt_time_end();
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  mpz_clear(z);
}

void scalar_clear_analysis(void *yarrow_rng, const struct ecc_curve *ecc)
{
  struct ecc_scalar key;
  FILE *randsc_scclear_fp;
  FILE *lhwsc_scclear_fp;
  FILE *hhwsc_scclear_fp;

  ecc_scalar_init(&key, ecc);
  randsc_scclear_fp = fopen("randsc_scclear.csv", "w");
  lhwsc_scclear_fp = fopen("lhwsc_scclear.csv", "w");
  hhwsc_scclear_fp = fopen("hhwsc_scclear.csv", "w");

  measure_clear(randsc_scclear_fp, &key, yarrow_rng,
                (nettle_random_func *)&yarrow256_random, ecc);
  measure_clear(lhwsc_scclear_fp, &key, yarrow_rng,
                (nettle_random_func *)&yarrow256_zeros, ecc);
  measure_clear(hhwsc_scclear_fp, &key, yarrow_rng,
                (nettle_random_func *)&yarrow256_ones, ecc);

  fclose(randsc_scclear_fp);
  fclose(lhwsc_scclear_fp);
  fclose(hhwsc_scclear_fp);
}

void measure_random(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                    nettle_random_func *random_func)
{
  unsigned int elapsed_time, i;
  mpz_t z;
  mpz_init(z);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    assert(cgt_time_start());
    ecc_scalar_random(key, yarrow_rng, random_func);
    elapsed_time = cgt_time_end();
    ecc_scalar_get(key, z);
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  mpz_clear(z);
}

void scalar_random_analysis(void *yarrow_rng, const struct ecc_curve *ecc)
{
  struct ecc_scalar key;
  FILE *randsc_scrandom_fp;
  FILE *lhwsc_scrandom_fp;
  FILE *hhwsc_scrandom_fp;

  ecc_scalar_init(&key, ecc);
  randsc_scrandom_fp = fopen("randsc_scrandom.csv", "w");
  lhwsc_scrandom_fp = fopen("lhwsc_scrandom.csv", "w");
  hhwsc_scrandom_fp = fopen("hhwsc_scrandom.csv", "w");

  measure_random(randsc_scrandom_fp, &key, yarrow_rng,
                 (nettle_random_func *)&yarrow256_random);
  measure_random(lhwsc_scrandom_fp, &key, yarrow_rng,
                 (nettle_random_func *)&yarrow256_zeros);
  measure_random(hhwsc_scrandom_fp, &key, yarrow_rng,
                 (nettle_random_func *)&yarrow256_ones);

  fclose(randsc_scrandom_fp);
  fclose(lhwsc_scrandom_fp);
  fclose(hhwsc_scrandom_fp);
  ecc_scalar_clear(&key);
}

void generate_data(uint8_t *data, size_t data_length, int type,
                   void *yarrow_rng)
{
  if (type == 0)
  {
    yarrow256_random(yarrow_rng, data_length, data);
  }
  else if (type == 1)
  {
    yarrow256_zeros(yarrow_rng, data_length, data);
  }
  else
  {
    yarrow256_ones(yarrow_rng, data_length, data);
  }
}

#define SIGN_DATA_LEN 128

void measure_sign(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                  nettle_random_func *random_func, int type)
{
  struct dsa_signature signature;
  unsigned int elapsed_time, i;
  mpz_t z;
  uint8_t *data;

  dsa_signature_init(&signature);
  mpz_init(z);
  data = malloc(SIGN_DATA_LEN);
  assert(data);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    generate_data(data, SIGN_DATA_LEN, type, yarrow_rng);
    ecc_scalar_random(key, yarrow_rng, random_func);
    assert(cgt_time_start());
    ecdsa_sign(key, yarrow_rng, (nettle_random_func *)&yarrow256_random,
               SIGN_DATA_LEN, data, &signature);
    elapsed_time = cgt_time_end();
    ecc_scalar_get(key, z);
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  mpz_clear(z);
  free(data);
  dsa_signature_clear(&signature);
}

void measure_sign_nonce(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                  nettle_random_func *random_func, int type)
{
  struct dsa_signature signature;
  unsigned int elapsed_time, i;
  mpz_t z;
  uint8_t *data;

  dsa_signature_init(&signature);
  mpz_init(z);
  data = malloc(SIGN_DATA_LEN);
  assert(data);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    generate_data(data, SIGN_DATA_LEN, type, yarrow_rng);
    ecc_scalar_random(key, yarrow_rng, (nettle_random_func *)&yarrow256_random);
    assert(cgt_time_start());
    ecdsa_sign(key, yarrow_rng, random_func,
               SIGN_DATA_LEN, data, &signature);
    elapsed_time = cgt_time_end();
    ecc_scalar_get(key, z);
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  mpz_clear(z);
  free(data);
  dsa_signature_clear(&signature);
}

// investigate use of RNG in ecdsa_sign
void sign_analysis(void *yarrow_rng, const struct ecc_curve *ecc)
{
  struct ecc_scalar key;
  FILE *randsc_sign_randomdata_fp;
  FILE *lhwsc_sign_randomdata_fp;
  FILE *hhwsc_sign_randomdata_fp;
  FILE *randsc_sign_hhwdata_fp;
  FILE *lhwsc_sign_hhwdata_fp;
  FILE *hhwsc_sign_hhwdata_fp;
  FILE *randsc_sign_lhwdata_fp;
  FILE *lhwsc_sign_lhwdata_fp;
  FILE *hhwsc_sign_lhwdata_fp;
  FILE *randsc_sign_randomdata_hhw_fp;
  FILE *randsc_sign_randomdata_lhw_fp;
  FILE *hhwsc_sign_randomdata_lhw_fp;
  FILE *lhwsc_sign_randomdata_hhw_fp;
  FILE *hhwsc_sign_randomdata_hhw_fp;
  FILE *lhwsc_sign_randomdata_lhw_fp;

  ecc_scalar_init(&key, ecc);
  randsc_sign_randomdata_fp = fopen("randsc_sign_randomdata.csv", "w");
  lhwsc_sign_randomdata_fp = fopen("lhwsc_sign_randomdata.csv", "w");
  hhwsc_sign_randomdata_fp = fopen("hhwsc_sign_randomdata.csv", "w");
  randsc_sign_hhwdata_fp = fopen("randsc_sign_hhwdata.csv", "w");
  lhwsc_sign_hhwdata_fp = fopen("lhwsc_sign_hhwdata.csv", "w");
  hhwsc_sign_hhwdata_fp = fopen("hhwsc_sign_hhwdata.csv", "w");
  randsc_sign_lhwdata_fp = fopen("randsc_sign_lhwdata.csv", "w");
  lhwsc_sign_lhwdata_fp = fopen("lhwsc_sign_lhwdata.csv", "w");
  hhwsc_sign_lhwdata_fp = fopen("hhwsc_sign_lhwdata.csv", "w");
  randsc_sign_randomdata_hhw_fp = fopen("randsc_sign_randomdata_hhw.csv", "w");
  randsc_sign_randomdata_lhw_fp = fopen("randsc_sign_randomdata_lhw.csv", "w");
  hhwsc_sign_randomdata_hhw_fp = fopen("hhwsc_sign_randomdata_hhw.csv", "w");
  lhwsc_sign_randomdata_lhw_fp = fopen("lhwsc_sign_randomdata_lhw.csv", "w");
  hhwsc_sign_randomdata_lhw_fp = fopen("hhwsc_sign_randomdata_lhw.csv", "w");
  lhwsc_sign_randomdata_hhw_fp = fopen("lhwsc_sign_randomdata_hhw.csv", "w");

  measure_sign(randsc_sign_randomdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_random, 0);
  measure_sign(lhwsc_sign_randomdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign(hhwsc_sign_randomdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_ones, 0);
  measure_sign(randsc_sign_hhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_random, 2);
  measure_sign(lhwsc_sign_hhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 2);
  measure_sign(hhwsc_sign_hhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_ones, 2);
  measure_sign(randsc_sign_lhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_random, 1);
  measure_sign(lhwsc_sign_lhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 1);
  measure_sign_nonce(randsc_sign_randomdata_hhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_ones, 0);
  measure_sign_nonce(randsc_sign_randomdata_lhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign_nonce(hhwsc_sign_randomdata_hhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign_nonce(lhwsc_sign_randomdata_lhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign_nonce(hhwsc_sign_randomdata_lhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign_nonce(lhwsc_sign_randomdata_hhw_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 0);
  measure_sign(lhwsc_sign_lhwdata_fp, &key, yarrow_rng,
               (nettle_random_func *)&yarrow256_zeros, 1);             
  
  fclose(randsc_sign_randomdata_fp);
  fclose(lhwsc_sign_randomdata_fp);
  fclose(hhwsc_sign_randomdata_fp);
  fclose(randsc_sign_hhwdata_fp);
  fclose(lhwsc_sign_hhwdata_fp);
  fclose(hhwsc_sign_hhwdata_fp);
  fclose(randsc_sign_lhwdata_fp);
  fclose(lhwsc_sign_lhwdata_fp);
  fclose(hhwsc_sign_lhwdata_fp);
  fclose(randsc_sign_randomdata_hhw_fp);
  fclose(randsc_sign_randomdata_lhw_fp);
  fclose(hhwsc_sign_randomdata_hhw_fp);
  fclose(lhwsc_sign_randomdata_lhw_fp);
  fclose(hhwsc_sign_randomdata_lhw_fp);
  fclose(lhwsc_sign_randomdata_hhw_fp);
  ecc_scalar_clear(&key);
}

void measure_mul(FILE *fp, struct ecc_scalar *key, void *yarrow_rng,
                 nettle_random_func *random_func, const struct ecc_curve *ecc)
{
  struct ecc_point pub;
  struct ecc_point result_p;
  unsigned int elapsed_time, i;
  mpz_t z;

  mpz_init(z);
  ecc_point_init(&pub, ecc);
  ecc_point_init(&result_p, ecc);

  for (i = 0; i < SAMPLE_SIZE; i++)
  {
    ecdsa_generate_keypair(&pub, key, yarrow_rng, random_func);
    assert(cgt_time_start());
    ecc_point_mul(&result_p, key, &pub);
    elapsed_time = cgt_time_end();
    ecc_scalar_get(key, z);
    gmp_fprintf(fp, "%064Zx;", z);
    fprintf(fp, "%u\n", elapsed_time);
  }

  ecc_point_clear(&pub);
  ecc_point_clear(&result_p);
  mpz_clear(z);
}

void scalar_point_mul_analysis(void *yarrow_rng, const struct ecc_curve *ecc)
{
  struct ecc_scalar key;
  FILE *randsc_pmul_fp;
  FILE *lhwsc_pmul_fp;
  FILE *hhwsc_pmul_fp;

  ecc_scalar_init(&key, ecc);
  randsc_pmul_fp = fopen("randsc_pmul.csv", "w");
  lhwsc_pmul_fp = fopen("lhwsc_pmul.csv", "w");
  hhwsc_pmul_fp = fopen("hhwsc_pmul.csv", "w");

  measure_mul(randsc_pmul_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_random, ecc);
  measure_mul(lhwsc_pmul_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_zeros, ecc);
  measure_mul(hhwsc_pmul_fp, &key, yarrow_rng,
              (nettle_random_func *)&yarrow256_ones, ecc);

  fclose(randsc_pmul_fp);
  fclose(lhwsc_pmul_fp);
  fclose(hhwsc_pmul_fp);
  ecc_scalar_clear(&key);
}

int main()
{
  const struct ecc_curve *ecc;
  struct yarrow256_ctx yarrow;
  time_t t;

  srand((unsigned)time(&t));
  ecc = nettle_get_secp_256r1();
  yarrow256_init(&yarrow, 0, NULL);
  if (seed_rng(&yarrow))
  {
    printf("Initialization of randomness generator failed.\n");
    return 1;
  }

  scalar_get_analysis(&yarrow, ecc);
  scalar_clear_analysis(&yarrow, ecc);
  sign_analysis(&yarrow, ecc);
  scalar_random_analysis(&yarrow, ecc);
  scalar_point_mul_analysis(&yarrow, ecc);
}
