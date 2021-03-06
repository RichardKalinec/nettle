/* Code was inspired by https://docs.oracle.com/cd/E19253-01/816-4863/chapter2-15/index.html
   and by example code from PV204. It was subsequently modified by Filip Gontko
   to suit our needs.
   Originally containing only functionality for keypair generation, signing and
   verification, Richard Kalinec added functions for encryption and decryption.
   It contains only functions for RSA operations.
*/
#include "rsa-pkcs11.h"

#define TEST_TOKEN_LABEL "pv204"
#define TEST_PIN "1234"


/* Get a slot with the given label, and if it exists, check whether it is capable of:
 * . signing and verifying with op_mech OR decrypting and encrypting with op_mech
 * . generating a key pair with kpgen_mech
 * Returns 0 when successful, 1 if the slot . */
int
getTokenSession(const char* tokenLabel, CK_SLOT_ID *pSlotID, CK_SLOT_INFO *pSlotInfo, CK_TOKEN_INFO *pTokenInfo,
	CK_MECHANISM_TYPE op_mech, CK_MECHANISM_TYPE kpgen_mech, int operations)
{
	if ((operations < 1) || (operations > 2))
	{
		printf("Invalid argument operations to getTokenSession()!n");
		exit(1);
	}
	
	int status = 0;
	CK_SLOT_ID pkcs11Slots[100];
	DWORD pkcs11SlotsCount = 100;
	ITEM_DATA_PKCS11READER readerInfo;
	m_pkcs11Mngr.Init(PKCS11_DLL);

	m_pkcs11Mngr.C_GetSlotList(FALSE, pkcs11Slots, &pkcs11SlotsCount);
	if (pkcs11SlotsCount > 0) {
		return 0;
	}
		
	CK_MECHANISM_INFO mech_info;
	bool bTestTokenFound = FALSE;
	bool bTestTokenUsable = FALSE;	
	for (DWORD i = 0; i < pkcs11SlotsCount; i++) {
		m_pkcs11Mngr.C_GetSlotInfo(pkcs11Slots[i], pSlotInfo);
		m_pkcs11Mngr.C_GetTokenInfo(pkcs11Slots[i], pTokenInfo);

		// IF MORE THAN 3 SPACES DETECTED, THAN CUT READER NAME
		TCHAR *pos = 0;
		if ((pos = strstr((TCHAR *) pTokenInfo->label, _T("   "))) != NULL) {
			memset(pTokenInfo->label + (pos - (TCHAR *) pTokenInfo->label) * sizeof(TCHAR), 0, sizeof(TCHAR));
		}

		// Do only when desired token was found
		if (strcmp((const char *) pTokenInfo->label, TESTING_TOKEN_LABEL) == 0) {
			bTestTokenFound = true;
			
			/* Check if this slot is capable of either signing and
			 * verifying or encrypting and decrypting with sv_mech.
			 */
			m_pkcs11Mngr.C_GetMechanismInfo(pkcs11Slots[i], op_mech, &mech_info);
	
			if (operations == 1)
			{
				if (!(mech_info.flags & CKF_SIGN &&
					mech_info.flags & CKF_VERIFY)) {
					continue;
				}
			}
			else if (operations == 2)
			{
				if (!(mech_info.flags & CKF_DECRYPT &&
					mech_info.flags & CKF_ENCRYPT)) {
					continue;
				}
			}
			
	
			/* Check if the slot is capable of key pair generation
			 * with kpgen_mech. */
	
			m_pkcs11Mngr.C_GetMechanismInfo(pkcs11Slots[i], kpgen_mech, &mech_info);
	
			if (!(mech_info.flags & CKF_GENERATE_KEY_PAIR)) {
				continue;
			}
	
			/* If we get this far, this slot supports our mechanisms. */
			*pSlotID = pkcs11Slots[i];
			bTestTokenUsable = true;
			break;
		}
	}

	if (!bTestTokenFound)
	{
		status = 1;
	}
	else if (!bTestTokenUsable)
	{
		status = 2;
	}		

	return status;
}

void
pkcs11_sign_verify_demo(CK_SESSION_HANDLE hSession, CK_MECHANISM* smech, CK_OBJECT_HANDLE privatekey,
	CK_OBJECT_HANDLE publickey, uchar_t* message, CK_ULONG messagelen, char* sign, CK_ULONG* slen,
	CK_ATTRIBUTE* getattributes)
{
	m_pkcs11Mngr.C_SignInit(hSession, smech, privatekey);

	m_pkcs11Mngr.C_Sign(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)sign, slen);

	fprintf(stdout, "Message was successfully signed with private key!\n");

	m_pkcs11Mngr.C_VerifyInit(hSession, smech, publickey);

	m_pkcs11Mngr.C_Verify(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)sign, *slen);

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
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
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
		{CKA_TOKEN, &truevalue, sizeof (truevalue)},
		{CKA_SENSITIVE, &truevalue, sizeof (truevalue)},
		{CKA_EXTRACTABLE, &falsevalue, sizeof (falsevalue)}
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

	m_pkcs11Mngr.Init(PKCS11_DLL);

	found_slot = getTokenSession(TEST_TOKEN_LABEL, &slotID, &slotInfo, &tokenInfo, smech.mechanism, genmech.mechanism, 1);

	if (!found_slot) {
		fprintf(stderr, "No usable slot was found.\n");
		(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);
		exit(error);
	}

	fprintf(stdout, "selected slot: %d\n", slotID);

	/* Open a session on the slot found */
	m_pkcs11Mngr.C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
	    &hSession);

	// Login user
	m_pkcs11Mngr.C_Login(hSession, CKU_USER, (CK_CHAR *) TEST_PIN, strlen(TEST_PIN));

	fprintf(stdout, "Generating keypair....\n");

	/* Generate Key pair for signing/verifying */
	m_pkcs11Mngr.C_GenerateKeyPair(hSession, &genmech, publickey_template,
	    (sizeof (publickey_template) / sizeof (CK_ATTRIBUTE)),
	    privatekey_template,
	    (sizeof (privatekey_template) / sizeof (CK_ATTRIBUTE)),
	    &publickey, &privatekey);

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
	m_pkcs11Mngr.C_EncryptInit(hSession, emech, publickey);

	m_pkcs11Mngr.C_Encrypt(hSession, (CK_BYTE_PTR)message, messagelen,
	    (CK_BYTE_PTR)ciphertext, clen);

	fprintf(stdout, "Message was successfully encrypted with public key!\n");

	m_pkcs11Mngr.C_DecryptInit(hSession, emech, privatekey);

	decrypted[BUFFERSIZ];
	declen = BUFFERSIZ;
	m_pkcs11Mngr.C_Decrypt(hSession, (CK_BYTE_PTR)ciphertext, *clen,
	    (CK_BYTE_PTR)decrypted, declen);
	    
	if (strcmp(message, decrypted) == 0) {
		fprintf(stdout, "Message was successfully decrypted with private key!\n");
	}
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
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
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
		{CKA_TOKEN, &truevalue, sizeof (truevalue)},
		{CKA_SENSITIVE, &truevalue, sizeof (truevalue)},
		{CKA_EXTRACTABLE, &falsevalue, sizeof (falsevalue)}
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

	/* Set up the encryption mechanism */
	emech.mechanism = CKM_RSA_PKCS;
	emech.pParameter = NULL_PTR;
	emech.ulParameterLen = 0;

	found_slot = getTokenSession(TEST_TOKEN_LABEL, &slotID, &slotInfo, &tokenInfo, smech.mechanism, genmech.mechanism, 2);

	if (!found_slot) {
		fprintf(stderr, "No usable slot was found.\n");
		(void) m_pkcs11Mngr.C_Finalize(NULL_PTR);
		exit(error);
	}

	fprintf(stdout, "selected slot: %d\n", slotID);

	/* Open a session on the slot found */
	m_pkcs11Mngr.C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
	    &hSession);

	// Login user
	m_pkcs11Mngr.C_Login(hSession, CKU_USER, (CK_CHAR *) TEST_PIN, strlen(TEST_PIN));

	fprintf(stdout, "Generating keypair....\n");

	/* Generate Key pair for encryption/decryption */
	m_pkcs11Mngr.C_GenerateKeyPair(hSession, &genmech, publickey_template,
	    (sizeof (publickey_template) / sizeof (CK_ATTRIBUTE)),
	    privatekey_template,
	    (sizeof (privatekey_template) / sizeof (CK_ATTRIBUTE)),
	    &publickey, &privatekey);

	/* Display the publickey. */
	template_size = sizeof (getattributes) / sizeof (CK_ATTRIBUTE);

	if (m_pkcs11Mngr.C_GetAttributeValue(hSession, publickey, getattributes,
	    template_size) != CKR_OK) {
		/* not fatal, we can still encrypt/decrypt if this failed */
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
			/* not fatal, we can still encrypt/decrypt if failed */
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
