/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : White-box encryption function
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2018/12/20      myseo       create.
 ******************************************************************************/

#include "whitebox.h"

#include "WBAES.h"
#include "WBAESGenerator.h"
#include "InputObjectBuffer.h"
#include "EncTools.h"

using namespace std;

int trust_signer_create_table(char **table)
{
	std::string outTable;
	char *phrase;
	unsigned char keyFromString[AES_BYTES];

	GenericAES defAES;
	defAES.init(0x11B, 0x03);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	for(int i=0; i<AES_BYTES; i++){
		keyFromString[i] = (unsigned char)(phrand() % 0x100);
	}

	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, true);
	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, false);

	//generator.save("/tmp/myseo_aes", genAES, &coding);
	outTable = genAES->save();
	//cout << "### MYSEO : Table Length = " << outTable.length() << endl;

	delete genAES;

	//table[1275881+1] = {0};
	int length = outTable.length();
	phrase = (char *) malloc (length + 1);
	memset (phrase, 0, length + 1);
	memcpy (phrase, outTable.c_str(), length);

	*table = phrase;

	return length;
}

int trust_signer_encrypt(char *table, int table_length, unsigned char *input, int in_length, unsigned char *output, bool encrypt)
{
	bool pkcs5Padding=true;
	bool cbc=true;
	unsigned char ivFromString[N_BYTES] = {0};

	GenericAES defAES;
	defAES.init(0x11B, 0x03);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	std::string inTable(table, table_length);
	//cout << "### MYSEO : Table Length = " << inTable.length() << endl;

	genAES->loadString(inTable);

	time_t cacc=0;
	clock_t pacc = 0;

	InputObjectBuffer<BYTE> ioib(in_length);
	ioib.write(input, in_length);
	InputObjectBuffer<BYTE> ioob(in_length*N_BYTES);

	EncTools::processData(!encrypt, genAES, &generator, &ioib, &ioob, &coding, pkcs5Padding, cbc, ivFromString, &cacc, &pacc);

	//cout << "### MYSEO : Enc Length = " << ioob.getPos() << endl;
	ioob.read(output, ioob.getPos());

	delete genAES;

	return ioob.getPos();
}

#ifdef TEST_WHITEBOX
int test_main(void)
{
	char *table = NULL;
	unsigned char encMessage[256] = {0};
	unsigned char decMessage[256] = {0};
	int table_length = 0;
	int output_length = 0;
	unsigned char message[] = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";

	memset (encMessage, 0, sizeof(encMessage));
	memset (decMessage, 0, sizeof(decMessage));

	cout << "### MYSEO : message = " << message << endl;
	table_length = trust_signer_create_table(&table);

	output_length = trust_signer_encrypt(table, table_length, message, strlen((char *)message), encMessage, false);
	cout << "### MYSEO : enc length = " << output_length << endl;

	output_length = trust_signer_encrypt(table, table_length, encMessage, output_length, decMessage, true);
	cout << "### MYSEO : dec message = " << decMessage << endl;

	if (table_length > 0) {
		free (table);
	}

	return 0;
}
#endif
