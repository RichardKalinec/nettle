int
generate_rsa_keys(FILE *ofile, void *yarrow, int keylen, int numkeys, int counter);

static int
gen_ecdsa_keys(void *yarrow_rng);
