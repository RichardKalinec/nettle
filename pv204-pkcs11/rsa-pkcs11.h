/* Code was inspired by https://docs.oracle.com/cd/E19253-01/816-4863/chapter2-15/index.html
   and by example code from PV204. It was subsequently modified by Filip Gontko
   to suit our needs.
   Originally containing only functionality for keypair generation, signing and
   verification, Richard Kalinec added functions for encryption and decryption.
   It contains only functions for RSA operations.
*/
#pragma once
#include "stdafx.h"
#include <list>
#include <cassert>
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
typedef unsigned long ULONG;

typedef char TCHAR;
typedef void* CK_VOID_PTR;


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

/* Define key template */
static CK_BBOOL truevalue = TRUE;
static CK_BBOOL falsevalue = FALSE;
static CK_ULONG modulusbits = 2048;
static CK_BYTE public_exponent[] = {65537};


int
getTokenSession(const char* tokenLabel, CK_SLOT_ID *pSlotID, CK_SLOT_INFO *pSlotInfo, CK_TOKEN_INFO *pTokenInfo,
	CK_MECHANISM_TYPE op_mech, CK_MECHANISM_TYPE kpgen_mech, int operations);
