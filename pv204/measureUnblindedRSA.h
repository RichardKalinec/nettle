void
measure_to_sexp(struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name);

void
measure_sign(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_sign_digest(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_compute_root(struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);

void
measure_decrypt(void *yarrow, struct rsa_public_key* pub, struct rsa_private_key* priv, char* ofile_name, uint8_t* data, size_t data_len);