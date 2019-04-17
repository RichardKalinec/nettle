#include "../ecc.h"
#include "../ecdsa.h"

int main(void)
{
    initialize_pkcs11();
    CK_SLOT_ID *slot_list = get_slots_list_pkcs11();
    CK_SESSION_HANDLE session = start_session_pkcs11(slot_list[0]);
    login_pkcs11(session, TEST_PIN);

    CK_OBJECT_HANDLE pubkey, privkey;
    size_t digest_length = 32;
    uint8_t digest[digest_length];
    CK_ULONG signature_length = SIG_LEN;
    CK_BYTE *signature = malloc(signature_length);

    for (size_t i = 0; i < digest_length; i++) {
        digest[i] = (CK_BYTE)rand();
    }

    ecdsa_generate_keypair_pkcs11(&pubkey, &privkey, session);
    ecdsa_sign_pkcs11(&privkey, session, digest_length, digest, signature);
    int verify_ret = ecdsa_verify_pkcs11(&pubkey, session, digest_length, digest, signature);
    if (verify_ret == 1)
        printf("Correct signature\n");
    else
        printf("Incorrect signature\n");    

    free(signature);
    destroy_keys_pkcs11(session, pubkey, privkey);
    free_slots_list_pkcs11(slot_list);
    end_session_pkcs11(session);
    logout_pkcs11(session);
    finalize_pkcs11();
}