int
generate_rsa_key(struct rsa_public_key* pub, struct rsa_private_key* priv, void *yarrow);

void
measure_from_sexp(struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name);

void
measure_sign_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_sign_digest_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_compute_root_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_decrypt_tr(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);