#ifndef PKCS11_STUB_H
#define PKCS11_STUB_H

//used for including pkcs#11 version 2.01
#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) \
returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
//used for including pkcs#11 version 2.01

#include "pkcs11.h"

/* These data types are platform/implementation dependent. */
#define CK_ENTRY          __declspec( dllexport ) 
#define CK_PTR            *
#define NULL_PTR          0
#pragma pack(push, cryptoki, 1)

#include "pkcs11_ft.h"  // function types for PKCS#11 functions

#define MAX_DLL_LIBS    10
#define SLOT_BASE_MULT  100
#define MAX_SLOTS       100
#define MAX_SESSIONS    100

#define SLOT_VIRTUAL_ID_BASE    1

#define CKR_TOO_MANY_SESSIONS   CKR_VENDOR_DEFINED + 1
/*
#ifndef HINSTANCE
    #define HINSTANCE    HANDLE
#endif
/**/


typedef struct _DLL_SLOT_INFO {
    bool        valid;
    HINSTANCE   dllLib;
    CK_SLOT_ID  realSlotID;
    CK_SLOT_ID  virtualSlotID;

    _DLL_SLOT_INFO() {
        clear();
    }
    void clear() {
        valid = FALSE;
        dllLib = NULL;
        realSlotID = 0;
        virtualSlotID = 0;
    }

} DLL_SLOT_INFO;

typedef struct _DLL_SESSION_INFO {
    bool                valid;
    HINSTANCE           dllLib;
    CK_SESSION_HANDLE   realSessionHandle;
    CK_SESSION_HANDLE   virtualSessionHandle;
    CK_SLOT_ID          virtualSlotID;


    _DLL_SESSION_INFO() {
        clear();
    }

    void clear() {
        valid = FALSE;
        dllLib = NULL;
        realSessionHandle = 0;
        virtualSessionHandle = 0;
        virtualSlotID = 0;
    }
} DLL_SESSION_INFO;

class CPKCS11Stub {
private:
    HINSTANCE           m_dllLibs[MAX_DLL_LIBS];
    DLL_SLOT_INFO       m_slotInfo[MAX_SLOTS];
    DLL_SESSION_INFO    m_sessionInfo[MAX_SESSIONS];
    CK_SESSION_HANDLE   m_nextVirtualSessionHandle;
public:
    CPKCS11Stub();
    ~CPKCS11Stub();
    CK_RV Init(const char* dllPaths);   // SET PATHS TO ALL PKCS#11 DLL'S GOING TO BE USED
protected:
    void ClearSlotInfos();
    void ClearSessionInfos();
    CK_RV GetSessionIndex(CK_SESSION_HANDLE virtSessionHandle, int* pSessionIndex);   
    CK_RV GetSlotIndex(CK_SLOT_ID virtSlotID, int* pSlotIndex);

public:
    const char* GetMechanimsName(CK_MECHANISM_TYPE mechType);
    const char* ErrorToString(CK_RV status);
    

public:    
/* General-purpose */

/* C_Initialize initializes the Cryptoki library. */
CK_RV C_Initialize(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
);
/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_RV C_Finalize(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);
///* C_GetInfo returns general information about Cryptoki. */
//CK_RV C_GetInfo(
//  CK_INFO_PTR   pInfo  /* location that receives information */
//);

/* C_GetFunctionList returns the function list. */
//CK_RV C_GetFunctionList(
//  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
//                                            * function list */
//);


/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_RV C_GetSlotList(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
);

/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
CK_RV C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
);

/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_RV C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);

/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_RV C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
);

/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_RV C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
);

/* C_InitToken initializes a token. */
CK_RV C_InitToken(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
);

/* C_InitPIN initializes the normal user's PIN. */
CK_RV C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
);

/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
);


/* Session management */

/* C_OpenSession opens a session between an application and a
 * token. */
CK_RV C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
);

/* C_CloseSession closes a session between an application and a
 * token. */
CK_RV C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);

/* C_CloseAllSessions closes all sessions with a token. */
CK_RV C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
);

/* C_GetSessionInfo obtains information about the session. */
CK_RV C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
);

/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_RV C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
);

/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_RV C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
);

/* C_Login logs a user into a token. */
CK_RV C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
);

/* C_Logout logs a user out from a token. */
CK_RV C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);


/* Object management */

/* C_CreateObject creates a new object. */
CK_RV C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
);

/* C_CopyObject copies an object, creating a new object for the
 * copy. */
CK_RV C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
);

/* C_DestroyObject destroys an object. */
CK_RV C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
);

/* C_GetObjectSize gets the size of an object in bytes. */
CK_RV C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
);

/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
CK_RV C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
);

/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
CK_RV C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
);

/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_RV C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
);

/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_RV C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
);

/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_RV C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);


/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_RV C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
);

/* C_Encrypt encrypts single-part data. */
CK_RV C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
);

/* C_EncryptUpdate continues a multiple-part encryption
 * operation. */
CK_RV C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);

/* C_EncryptFinal finishes a multiple-part encryption
 * operation. */
CK_RV C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);

/* C_DecryptInit initializes a decryption operation. */
CK_RV C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
);

/* C_Decrypt decrypts encrypted data in a single part. */
CK_RV C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
);

/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
CK_RV C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);

/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
CK_RV C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);


/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_RV C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
);

/* C_Digest digests data in a single part. */
CK_RV C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
);

/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
CK_RV C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
);

/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_RV C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
);

/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
CK_RV C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
);


/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
CK_RV C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
);

/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
CK_RV C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_RV C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
);

/* C_SignFinal finishes a multiple-part signature operation, 
 * returning the signature. */
CK_RV C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_RV C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
);

/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_RV C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);


/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
CK_RV C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */ 
);

/* C_Verify verifies a signature in a single-part operation, 
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
CK_RV C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
);

/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_RV C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
);

/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
CK_RV C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
);

/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
);

/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
);


/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_RV C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_RV C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
);

/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_RV C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);

/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_RV C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
);


/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
CK_RV C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
);

/* C_GenerateKeyPair generates a public-key/private-key pair, 
 * creating new key objects. */
CK_RV C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
);

/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
);

/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_RV C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
);

/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_RV C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
);


/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
CK_RV C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
);

/* C_GenerateRandom generates random data. */
CK_RV C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
);


/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
CK_RV C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);

/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
CK_RV C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);


/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
//CK_RV C_WaitForSlotEvent(
//  CK_FLAGS flags,        /* blocking/nonblocking flag */
//  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
//  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
//);
  

};

#endif