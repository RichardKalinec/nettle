/* ecdsa-keygen.c

   Copyright (C) 2013 Niels Möller

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

/* Development of Nettle's ECC support was funded by the .SE Internet Fund. */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "ecdsa.h"
#include "ecc-internal.h"
#include "nettle-internal.h"

void
ecdsa_generate_keypair_pkcs11 (CK_OBJECT_HANDLE_PTR pubkey, 
      CK_OBJECT_HANDLE_PTR privkey, CK_SESSION_HANDLE session)
{
  CK_BBOOL ctrue  = CK_TRUE;
  CK_BBOOL cfalse = CK_FALSE;

  // Missing mechanism to establish ECC parameters based on a curve
  CK_BYTE params[] = {1};

  CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_ATTRIBUTE pub_template[] = {
    {CKA_CLASS, &pub_class, sizeof(pub_class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    {CKA_TOKEN, &ctrue, sizeof(ctrue)},
    {CKA_EC_PARAMS, params, sizeof(params)},
    {CKA_VERIFY, &ctrue, sizeof(ctrue)}
  };

  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE priv_template[] = {
    {CKA_EXTRACTABLE, &cfalse, sizeof(cfalse)},
    {CKA_CLASS, &priv_class, sizeof(priv_class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    {CKA_TOKEN, &ctrue, sizeof(ctrue)},
    {CKA_SENSITIVE, &ctrue, sizeof(ctrue)},
    {CKA_DERIVE, &ctrue, sizeof(ctrue)},
    {CKA_EC_PARAMS, params, sizeof(params)}
  };

  CK_RV ret;
  CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

  ret = C_GenerateKeyPair(session, &mechanism,
                          pub_template, sizeof(pub_template)/sizeof(pub_template[0]),
                          priv_template, sizeof(priv_template)/sizeof(priv_template[0]),
                          pubkey, privkey);
  check_return_value_pkcs11(ret, "C_GenerateKeyPair()");
}

void
ecdsa_generate_keypair (struct ecc_point *pub,
			struct ecc_scalar *key,
			void *random_ctx, nettle_random_func *random)
{
  TMP_DECL(p, mp_limb_t, 3*ECC_MAX_SIZE + ECC_MUL_G_ITCH (ECC_MAX_SIZE));
  const struct ecc_curve *ecc = pub->ecc;
  mp_size_t itch = 3*ecc->p.size + ecc->mul_g_itch;

  assert (key->ecc == ecc);

  TMP_ALLOC (p, itch);

  ecc_mod_random (&ecc->q, key->p, random_ctx, random, p);
  ecc->mul_g (ecc, p, key->p, p + 3*ecc->p.size);
  ecc->h_to_a (ecc, 0, pub->p, p, p + 3*ecc->p.size);
}
