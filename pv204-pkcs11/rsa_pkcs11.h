/* Taken by Filip Gontko from  and subsequently modified to suit our needs.
   Originally containing only functionality for keypair generation, signing and
   verification, Richard Kalinec added functions for encryption and decryption.
   It contains only functions for RSA operations.

   Code was inspired by https://docs.oracle.com/cd/E19253-01/816-4863/chapter2-15/index.html
   and by example code from PV204.
*/
#pragma once
#include "stdafx.h"
#include <list>
#include <cassert>
#include <iostream>
#include <tic.h>

#include "pkcs11stub.h"
#include <cstdint>

typedef uint8_t  CHAR;
typedef uint16_t WORD;
typedef uint32_t DWORD;

typedef int8_t  BYTE;
typedef int16_t SHORT;
typedef int32_t LONG;

typedef LONG INT;
typedef INT BOOL;

using namespace std;

#define PKCS11_DLL "softhsm2.dll"

#define MAX_READER_NAME_LENGTH  256
#define TESTING_TOKEN_LABEL		 "pv204"
typedef unsigned long ULONG;
#define TEST_PIN    "1234"
//typedef unsigned int DWORD;
typedef char TCHAR;
typedef void* CK_VOID_PTR;

#define TS_ASSERT(x) assert(x)
#define TS_FAIL(x) { cout << x; assert(false); }
//#define _T(x) x


typedef struct _ITEM_DATA_PKCS11READER {
	ULONG               slotID;
	ULONG               hSession;
	char                readerName[MAX_READER_NAME_LENGTH];
	bool                bCardPresent;
	char                cardATR[MAX_READER_NAME_LENGTH];

	_ITEM_DATA_PKCS11READER() {
		clear();
	}

	void clear() {
		slotID = 0;
		hSession = NULL;
		memset(readerName, 0, sizeof(readerName));
		bCardPresent = false;
		memset(cardATR, 0, sizeof(cardATR));
	}
} ITEM_DATA_PKCS11READER;

typedef list<ITEM_DATA_PKCS11READER> lp11r;

CPKCS11Stub m_pkcs11Mngr;

int getTokenSession(CK_SLOT_ID *pSlotID, CK_SLOT_INFO *pSlotInfo, CK_TOKEN_INFO *pTokenInfo) {
		int status = 0;
		CK_SLOT_ID pkcs11Slots[100];
		DWORD pkcs11SlotsCount = 100;
		ITEM_DATA_PKCS11READER readerInfo;
		m_pkcs11Mngr.Init(PKCS11_DLL);

		TS_ASSERT(m_pkcs11Mngr.C_GetSlotList(FALSE, pkcs11Slots, &pkcs11SlotsCount) == CKR_OK);
		TS_ASSERT(pkcs11SlotsCount > 0);
		bool bTestTokenFound = FALSE;
		for (DWORD i = 0; i < pkcs11SlotsCount; i++) {
			TS_ASSERT(m_pkcs11Mngr.C_GetSlotInfo(pkcs11Slots[i], pSlotInfo) == CKR_OK);
			TS_ASSERT(m_pkcs11Mngr.C_GetTokenInfo(pkcs11Slots[i], pTokenInfo) == CKR_OK);

			// IF MORE THAN 3 SPACES DETECTED, THAN CUT READER NAME
			TCHAR *pos = 0;
			if ((pos = strstr((TCHAR *) pTokenInfo->label, _T("   "))) != NULL) {
				memset(pTokenInfo->label + (pos - (TCHAR *) pTokenInfo->label) * sizeof(TCHAR), 0, sizeof(TCHAR));
			}

			// Do only when testing token was found
			if (strcmp((const char *) pTokenInfo->label, TESTING_TOKEN_LABEL) == 0) {
				bTestTokenFound = true;
				*pSlotID = pkcs11Slots[i];
				break;
			}
		}

		if (!bTestTokenFound) status = CKR_TOKEN_NOT_PRESENT;

		return status;
	}

	/* Define key template */
static CK_BBOOL truevalue = TRUE;
static CK_BBOOL falsevalue = FALSE;
static CK_ULONG modulusbits = 1024;
static CK_BYTE public_exponent[] = {3};

/* Find a slot capable of:
 * . signing and verifying with op_mech OR decrypting and encrypting with op_mech
 * . generating a key pair with kpgen_mech
 * Returns B_TRUE when successful. */
boolean_t GetMySlot(CK_MECHANISM_TYPE op_mech, CK_MECHANISM_TYPE kpgen_mech,
    CK_SLOT_ID_PTR pSlotID, int operations)
{
	if ((operations < 1) || (operations > 2))
	{
		printf("Invalid argument operations to GetMySlot()!n");
		exit(1);
	}
	
	CK_SLOT_ID_PTR pSlotList = NULL_PTR;
	CK_SLOT_ID SlotID;
	CK_ULONG ulSlotCount = 0;
	CK_MECHANISM_INFO mech_info;
	int i;
	boolean_t returnval = B_FALSE;

	if ((m_pkcs11Mngr.C_GetSlotList(0, NULL_PTR, &ulSlotCount) == CKR_OK) && (ulSlotCount > 0)) {
		fprintf(stdout, "slotCount = %d\n", ulSlotCount);
		pSlotList = malloc(ulSlotCount * sizeof (CK_SLOT_ID));

		if (pSlotList == NULL) {
			fprintf(stderr, "System error: unable to allocate "
			    "memory\n");
			return (returnval);
		}

		/* Get the slot list for processing */
		if (m_pkcs11Mngr.C_GetSlotList(0, pSlotList, &ulSlotCount) != CKR_OK) {
			fprintf(stderr, "GetSlotList failed: unable to get "
			    "slot count.\n");
			if (pSlotList)
				free(pSlotList);
			return (returnval);
		}
	} else {
		fprintf(stderr, "GetSlotList failed: unable to get slot "
		    "list.\n");
		return (returnval);
	}

	/* Find a slot capable of specified mechanism */
	for (i = 0; i < ulSlotCount; i++) {
		SlotID = pSlotList[i];

		/* Check if this slot is capable of signing and
		 * verifying with sv_mech. */

		if (m_pkcs11Mngr.C_GetMechanismInfo(SlotID, op_mech, &mech_info); != CKR_OK) {
			continue;
		}

		if (operations == 1)
		{
			if (!(mech_info.flags & CKF_SIGN &&
				mech_info.flags & CKF_VERIFY)) {
				continue;
			}
		}
		esle if (operations == 2)
		{
			if (!(mech_info.flags & CKF_DECRYPT &&
				mech_info.flags & CKF_ENCRYPT)) {
				continue;
			}
		}
		

		/* Check if the slot is capable of key pair generation
		 * with kpgen_mech. */

		if (m_pkcs11Mngr.C_GetMechanismInfo(SlotID, kpgen_mech, &mech_info) != CKR_OK) {
			continue;
		}

		if (!(mech_info.flags & CKF_GENERATE_KEY_PAIR)) {
			continue;
		}

		/* If we get this far, this slot supports our mechanisms. */
		returnval = B_TRUE;
		*pSlotID = SlotID;
		break;
	}

	if (pSlotList)
		free(pSlotList);
	return (returnval);
}

void
pkcs11_sign_verify_demo(CK_SESSION_HANDLE hSession, CK_MECHANISM* smech, CK_OBJECT_HANDLE privatekey,
	CK_OBJECT_HANDLE publickey, uchar_t* message, CK_ULONG messagelen, char* sign, CK_ULONG* slen,
	CK_ATTRIBUTE* getattributes)
{
	TS_ASSERT(m_pkcs11Mngr.C_SignInit(hSession, smech, privatekey) == CKR_OK);

	TS_ASSERT(m_pkcs11Mngr.C_Sign(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)sign, slen) == CKR_OK);

	fprintf(stdout, "Message was successfully signed with private key!\n");

	TS_ASSERT(m_pkcs11Mngr.C_VerifyInit(hSession, smech, publickey) == CKR_OK);

	TS_ASSERT(m_pkcs11Mngr.C_Verify(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)sign, *slen) == CKR_OK);

	fprintf(stdout, "Message was successfully verified with public key!\n");
	
	// Close session
	(void) m_pkcs11Mngr.C_CloseSession(hSession);
	
	// Perform final cleanup
	(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);

	for (i = 0; i < template_size; i++) {
		if (getattributes[i].pValue != NULL)
			free(getattributes[i].pValue);
	}
}

/* Example signs and verifies a simple string, using a public/private
 * key pair. */
void
kgsvDemo(int argc, char **argv)
{
	CK_MECHANISM genmech, smech;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_INFO sessInfo;
	CK_SLOT_ID slotID;
	int error, i = 0;

	CK_OBJECT_HANDLE privatekey, publickey;

    /* Set public key. */
	CK_ATTRIBUTE publickey_template[] = {
		{CKA_VERIFY, &truevalue, sizeof (truevalue)},
		{CKA_MODULUS_BITS, &modulusbits, sizeof (modulusbits)},
		{CKA_PUBLIC_EXPONENT, &public_exponent,
		    sizeof (public_exponent)}
	};

    /* Set private key. */
	CK_ATTRIBUTE privatekey_template[] = {
		{CKA_SIGN, &truevalue, sizeof (truevalue)},
		{CKA_TOKEN, &falsevalue, sizeof (falsevalue)},
		{CKA_SENSITIVE, &truevalue, sizeof (truevalue)},
		{CKA_EXTRACTABLE, &truevalue, sizeof (truevalue)}
	};

    /* Create sample message. */
	CK_ATTRIBUTE getattributes[] = {
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
	};

	CK_ULONG messagelen, slen, template_size;

	boolean_t found_slot = B_FALSE;
	uchar_t *message = (uchar_t *)"Simple message for signing & verifying.";
	uchar_t *modulus, *pub_exponent;
	char sign[BUFFERSIZ];
	slen = BUFFERSIZ;

	messagelen = strlen((char *)message);

	/* Set up mechanism for generating key pair */
	genmech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	genmech.pParameter = NULL_PTR;
	genmech.ulParameterLen = 0;

	/* Set up the signing mechanism */
	smech.mechanism = CKM_RSA_PKCS;
	smech.pParameter = NULL_PTR;
	smech.ulParameterLen = 0;

	TS_ASSERT(m_pkcs11Mngr.Init(PKCS11_DLL) == CKR_OK);

	found_slot = GetMySlot(smech.mechanism, genmech.mechanism, &slotID, 1);

	if (!found_slot) {
		fprintf(stderr, "No usable slot was found.\n");
		(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);
		exit(error);
	}

	fprintf(stdout, "selected slot: %d\n", slotID);

	/* Open a session on the slot found */
	TS_ASSERT(m_pkcs11Mngr.C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
	    &hSession) == CKR_OK);

	// Login user
	TS_ASSERT(m_pkcs11Mngr.C_Login(hSession, CKU_USER, (CK_CHAR *) TEST_PIN, strlen(TEST_PIN)) == CKR_OK);

	fprintf(stdout, "Generating keypair....\n");

	/* Generate Key pair for signing/verifying */
	TS_ASSERT(m_pkcs11Mngr.C_GenerateKeyPair(hSession, &genmech, publickey_template,
	    (sizeof (publickey_template) / sizeof (CK_ATTRIBUTE)),
	    privatekey_template,
	    (sizeof (privatekey_template) / sizeof (CK_ATTRIBUTE)),
	    &publickey, &privatekey) == CKR_OK);

	/* Display the publickey. */
	template_size = sizeof (getattributes) / sizeof (CK_ATTRIBUTE);

	if (m_pkcs11Mngr.C_GetAttributeValue(hSession, publickey, getattributes,
	    template_size) != CKR_OK) {
		/* not fatal, we can still sign/verify if this failed */
		fprintf(stderr, "C_GetAttributeValue: rv = 0x%.8X\n", rv);
		error = 1;
	} else {
		/* Allocate memory to hold the data we want */
		for (i = 0; i < template_size; i++) {
			getattributes[i].pValue = 
			    malloc (getattributes[i].ulValueLen * 
				sizeof(CK_VOID_PTR));
			if (getattributes[i].pValue == NULL) {
				int j;
				for (j = 0; j < i; j++)
					free(getattributes[j].pValue);
				pkcs11_sign_verify_demo(hSession, &smech, privatekey,
					publickey, message, messagelen, sign, &slen,
					getattributes);
				return;
			}
		}

		/* Call again to get actual attributes */
		if (m_pkcs11Mngr.C_GetAttributeValue(hSession, publickey, getattributes,
	    template_size) != CKR_OK) {
			/* not fatal, we can still sign/verify if failed */
			fprintf(stderr,
			    "C_GetAttributeValue: rv = 0x%.8X\n", rv);
			error = 1;
		} else {
			/* Display public key values */
			fprintf(stdout, "Public Key data:\n\tModulus bits: "
			    "%d\n", 
			    *((CK_ULONG_PTR)(getattributes[0].pValue)));

			fprintf(stdout, "\tModulus: ");
			modulus = (uchar_t *)getattributes[1].pValue;
			for (i = 0; i < getattributes[1].ulValueLen; i++) {
				fprintf(stdout, "%.2x", modulus[i]);
			}

			fprintf(stdout, "\n\tPublic Exponent: ");
			pub_exponent = (uchar_t *)getattributes[2].pValue;
			for (i = 0; i< getattributes[2].ulValueLen; i++) {
				fprintf(stdout, "%.2x", pub_exponent[i]);
			}
			fprintf(stdout, "\n");
		}
	}
	
	pkcs11_sign_verify_demo(hSession, &smech, privatekey,
		publickey, message, messagelen, sign, &slen,
		getattributes);
	return;
}

void
pkcs11_encrypt_decrypt_demo(CK_SESSION_HANDLE hSession, CK_MECHANISM* emech, CK_OBJECT_HANDLE privatekey,
	CK_OBJECT_HANDLE publickey, uchar_t* message, CK_ULONG messagelen, char* ciphertext, CK_ULONG* clen,
	CK_ATTRIBUTE* getattributes)
{
	TS_ASSERT(m_pkcs11Mngr.C_EncryptInit(hSession, emech, publickey) == CKR_OK);

	TS_ASSERT(m_pkcs11Mngr.C_Encrypt(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)ciphertext, clen) == CKR_OK);

	fprintf(stdout, "Message was successfully encrypted with public key!\n");

	TS_ASSERT(m_pkcs11Mngr.C_DecryptInit(hSession, emech, privatekey) == CKR_OK);

	decrypted[BUFFERSIZ];
	declen = BUFFERSIZ;
	TS_ASSERT(m_pkcs11Mngr.C_Decrypt(hSession, (CK_BYTE_PTR)ciphertext, *clen,
	    (CK_BYTE_PTR)decrypted, declen) == CKR_OK);
	    
	TS_ASSERT(strcmp(message, decrypted) == 0);

	fprintf(stdout, "Message was successfully decrypted with private key!\n");
	
	// Close session
	(void) m_pkcs11Mngr.C_CloseSession(hSession);
	
	// Perform final cleanup
	(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);

	for (i = 0; i < template_size; i++) {
		if (getattributes[i].pValue != NULL)
			free(getattributes[i].pValue);
	}
}

/* Example encrypts and decrypts a simple string, using a public/private
 * key pair. */
void
edDemo(int argc, char **argv)
{
	CK_MECHANISM genmech, emech;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_INFO sessInfo;
	CK_SLOT_ID slotID;
	int error, i = 0;

	CK_OBJECT_HANDLE privatekey, publickey;

    /* Set public key. */
	CK_ATTRIBUTE publickey_template[] = {
		{CKA_ENCRYPT, &truevalue, sizeof (truevalue)},
		{CKA_MODULUS_BITS, &modulusbits, sizeof (modulusbits)},
		{CKA_PUBLIC_EXPONENT, &public_exponent,
		    sizeof (public_exponent)}
	};

    /* Set private key. */
	CK_ATTRIBUTE privatekey_template[] = {
		{CKA_DECRYPT, &truevalue, sizeof (truevalue)},
		{CKA_TOKEN, &falsevalue, sizeof (falsevalue)},
		{CKA_SENSITIVE, &truevalue, sizeof (truevalue)},
		{CKA_EXTRACTABLE, &truevalue, sizeof (truevalue)}
	};

    /* Create sample message. */
	CK_ATTRIBUTE getattributes[] = {
		{CKA_MODULUS_BITS, NULL_PTR, 0},
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
	};

	CK_ULONG messagelen, template_size;

	boolean_t found_slot = B_FALSE;
	uchar_t *message = (uchar_t *)"Simple message for encrypting & decrypting.";
	uchar_t *modulus, *pub_exponent;
	char ciphertext[BUFFERSIZ];
	clen = BUFFERSIZ;

	messagelen = strlen((char *)message);

	/* Set up mechanism for generating key pair */
	genmech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	genmech.pParameter = NULL_PTR;
	genmech.ulParameterLen = 0;

	/* Set up the signing mechanism */
	emech.mechanism = CKM_RSA_PKCS;
	emech.pParameter = NULL_PTR;
	emech.ulParameterLen = 0;

	TS_ASSERT(m_pkcs11Mngr.Init(PKCS11_DLL) == CKR_OK);

	found_slot = GetMySlot(smech.mechanism, genmech.mechanism, &slotID, 2);

	if (!found_slot) {
		fprintf(stderr, "No usable slot was found.\n");
		(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);
		exit(error);
	}

	fprintf(stdout, "selected slot: %d\n", slotID);

	/* Open a session on the slot found */
	TS_ASSERT(m_pkcs11Mngr.C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
	    &hSession) == CKR_OK);

	// Login user
	TS_ASSERT(m_pkcs11Mngr.C_Login(hSession, CKU_USER, (CK_CHAR *) TEST_PIN, strlen(TEST_PIN)) == CKR_OK);

	fprintf(stdout, "Generating keypair....\n");

	/* Generate Key pair for signing/verifying */
	TS_ASSERT(m_pkcs11Mngr.C_GenerateKeyPair(hSession, &genmech, publickey_template,
	    (sizeof (publickey_template) / sizeof (CK_ATTRIBUTE)),
	    privatekey_template,
	    (sizeof (privatekey_template) / sizeof (CK_ATTRIBUTE)),
	    &publickey, &privatekey) == CKR_OK);

	/* Display the publickey. */
	template_size = sizeof (getattributes) / sizeof (CK_ATTRIBUTE);

	if (m_pkcs11Mngr.C_GetAttributeValue(hSession, publickey, getattributes,
	    template_size) != CKR_OK) {
		/* not fatal, we can still decrypt/encrypt if this failed */
		fprintf(stderr, "C_GetAttributeValue: rv = 0x%.8X\n", rv);
		error = 1;
	} else {
		/* Allocate memory to hold the data we want */
		for (i = 0; i < template_size; i++) {
			getattributes[i].pValue = 
			    malloc (getattributes[i].ulValueLen * 
				sizeof(CK_VOID_PTR));
			if (getattributes[i].pValue == NULL) {
				int j;
				for (j = 0; j < i; j++)
					free(getattributes[j].pValue);
				pkcs11_encrypt_decrypt_demo(hSession, &emech, privatekey,
					publickey, message, messagelen, ciphertext, &clen,
					getattributes);
				return;
			}
		}

		/* Call again to get actual attributes */
		if (m_pkcs11Mngr.C_GetAttributeValue(hSession, publickey, getattributes,
	    template_size) != CKR_OK) {
			/* not fatal, we can still sign/verify if failed */
			fprintf(stderr,
			    "C_GetAttributeValue: rv = 0x%.8X\n", rv);
			error = 1;
		} else {
			/* Display public key values */
			fprintf(stdout, "Public Key data:\n\tModulus bits: "
			    "%d\n", 
			    *((CK_ULONG_PTR)(getattributes[0].pValue)));

			fprintf(stdout, "\tModulus: ");
			modulus = (uchar_t *)getattributes[1].pValue;
			for (i = 0; i < getattributes[1].ulValueLen; i++) {
				fprintf(stdout, "%.2x", modulus[i]);
			}

			fprintf(stdout, "\n\tPublic Exponent: ");
			pub_exponent = (uchar_t *)getattributes[2].pValue;
			for (i = 0; i< getattributes[2].ulValueLen; i++) {
				fprintf(stdout, "%.2x", pub_exponent[i]);
			}
			fprintf(stdout, "\n");
		}
	}
	
	pkcs11_encrypt_decrypt_demo(hSession, &emech, privatekey,
		publickey, message, messagelen, ciphertext, &clen,
		getattributes);
	return;
}

int
main(int argc, char** argv)
{
	kgsvDemo();
	edDemo();
}