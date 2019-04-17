/* 
 * Functions for the set-up of PKCS#11 session were heavily inspired by
 * https://www.dnssec.cz/files/nic/doc/hsm.pdf
 *
 * The rest of the definitions was based on the official specification 
 * http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
 * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
 * 
 * Unfortunately, not enough time to finish
 */

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pkcs11.h"

#define SLOT_COUNT 128
#define ECC_BITS 256
#define SIG_LEN ECC_BITS/4

CK_UTF8CHAR TEST_PIN[] = "1234";

void check_return_value_pkcs11(CK_RV rv, const char *message);

void initialize_pkcs11(void);

CK_SLOT_ID *get_slots_list_pkcs11(void);

void free_slots_list_pkcs11(CK_SLOT_ID *slotIDs);

CK_SESSION_HANDLE start_session_pkcs11(CK_SLOT_ID slotID);

void login_pkcs11(CK_SESSION_HANDLE session, CK_BYTE *pin);

void logout_pkcs11(CK_SESSION_HANDLE session);

void end_session_pkcs11(CK_SESSION_HANDLE session);

void finalize_pkcs11(void);

void destroy_keys_pkcs11(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pubkey,
                         CK_OBJECT_HANDLE privkey);