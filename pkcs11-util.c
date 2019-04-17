#include "pkcs11-util.h"

void check_return_value_pkcs11(CK_RV rv, const char *message)
{
    if (rv != CKR_OK)
    {
        fprintf(stderr, "Error at %s: %u\n", message, (unsigned int)rv);
        exit(EXIT_FAILURE);
    }
}

void initialize_pkcs11(void)
{
    CK_RV rv;
    rv = C_Initialize(NULL);
    check_return_value_pkcs11(rv, "C_Initialize()");
}

CK_SLOT_ID *get_slots_list_pkcs11(void)
{
    CK_RV rv;
    CK_ULONG slotCount = SLOT_COUNT;
    CK_SLOT_ID *slotIDs = malloc(sizeof(CK_SLOT_ID) * slotCount);
    rv = C_GetSlotList(CK_TRUE, slotIDs, &slotCount);
    check_return_value_pkcs11(rv, "C_GetSlotList()");
    if (slotCount < 1) {
        fprintf(stderr, "Error: could not find any slots\n");
        exit(1);
    }

    return slotIDs;
}

void free_slots_list_pkcs11(CK_SLOT_ID *slotIDs)
{
    free(slotIDs);
}

CK_SESSION_HANDLE start_session_pkcs11(CK_SLOT_ID slotID)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
    check_return_value_pkcs11(rv, "C_OpenSession()");
    return session;
}

void login_pkcs11(CK_SESSION_HANDLE session, CK_BYTE *pin)
{
    CK_RV rv;
    if (pin) {
        rv = C_Login(session, CKU_USER, pin, strlen((char *)pin));
        check_return_value_pkcs11(rv, "C_Login()");
    }
}

void logout_pkcs11(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    rv = C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN) {
        check_return_value_pkcs11(rv, "C_Logout()");
    }
}

void end_session_pkcs11(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    rv = C_CloseSession(session);
    check_return_value_pkcs11(rv, "C_CloseSession()");
}

void finalize_pkcs11(void)
{
    C_Finalize(NULL);
}

void destroy_keys_pkcs11(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pubkey,
                         CK_OBJECT_HANDLE privkey)
{
    CK_RV rv;
    rv = C_DestroyObject(session, pubkey);
    check_return_value_pkcs11(rv, "C_DestroyObject()");
    rv = C_DestroyObject(session, privkey);
    check_return_value_pkcs11(rv, "C_DestroyObject()");
}