/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : JNI function
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2019/01/08      myseo       create.
 * 2019/01/17      myseo       coin type added.
 * 2019/01/22      myseo       AES256, SHA512 using.
 * 2019/01/23      myseo       Android <-> Shell compile define added.
 * 2019/01/31      myseo       BIP44 spec added.
 * 2019/02/02      myseo       Base64 source added.
 * 2019/02/07      myseo       Recovery data GET/SET function added.
 ******************************************************************************/

#ifdef __ANDROID__
#include <jni.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "secp256k1.h"
#include "base32.h"
#include "base58.h"
#include "hasher.h"
#include "address.h"
#include "rand.h"
#include "memzero.h"

#include "aes.h"
#include "sha2.h"

#include "WBAES.h"
#include "WBAESGenerator.h"
#include "InputObjectBuffer.h"
#include "EncTools.h"

#include "coin.h"
#include "whitebox.h"
#include "base64.h"


#define DEBUG_TRUST_SIGNER      1
#ifdef DEBUG_TRUST_SIGNER
char hexbuf[256];

#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG		"### MYSEO "
#define LOGV(...)	__android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...)	__android_log_print(ANDROID_LOG_DEBUG  , LOG_TAG, __VA_ARGS__)
#define LOGI(...)	__android_log_print(ANDROID_LOG_INFO   , LOG_TAG, __VA_ARGS__)
#define LOGW(...)	__android_log_print(ANDROID_LOG_WARN   , LOG_TAG, __VA_ARGS__)
#define LOGE(...)	__android_log_print(ANDROID_LOG_ERROR  , LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...)	printf(__VA_ARGS__)
#endif
#endif

#ifdef __ANDROID__
static char *jbyteArry2char (JNIEnv *env, jbyteArray in)
{
	int len = env->GetArrayLength (in);
	char *ret = (char *) malloc ((size_t)len);

	if (ret != NULL) {
		jbyte *jin = env->GetByteArrayElements (in, 0);
		memcpy (ret, (const char *) jin, (size_t) len);
		env->ReleaseByteArrayElements(in, jin, 0);
	}

	return ret;
}

static jbyteArray char2JbyteArry (JNIEnv *env, char *in, int len)
{
	jbyteArray array = env->NewByteArray (len);

	if (in != NULL && array != NULL) {
		env->SetByteArrayRegion(array, 0, len, (jbyte *) in);
	} else {
		return NULL;
	}

	return array;
}

static unsigned char *jbyteArry2uchar (JNIEnv *env, jbyteArray in)
{
	int len = env->GetArrayLength (in);
	unsigned char *ret = (unsigned char *) malloc ((size_t)len);

	if (ret != NULL) {
		jbyte *jin = env->GetByteArrayElements (in, 0);
		memcpy (ret, (const char *) jin, (size_t) len);
		env->ReleaseByteArrayElements(in, jin, 0);
	}

	return ret;
}

static jbyteArray uchar2JbyteArry (JNIEnv *env, unsigned char *in, int len)
{
	jbyteArray array = env->NewByteArray (len);

	if (in != NULL && array != NULL) {
		env->SetByteArrayRegion(array, 0, len, (jbyte *) in);
	} else {
		return NULL;
	}

	return array;
}
#endif

static int encryptAES256 (unsigned char *key, int key_len, unsigned char *message, int message_len, unsigned char *buffer) {
	int ret = 0;
	int enc_count = 1;

	aes_encrypt_ctx ctx_aes;
	uint8_t iv[AES_BLOCK_SIZE] ={0};
	uint8_t enc_key[SHA3_256_DIGEST_LENGTH] = {0};

	SHA512_CTX ctx_sha;
	unsigned char hashbuf[SHA3_512_DIGEST_LENGTH];

	sha512_Init (&ctx_sha);
	sha512_Update (&ctx_sha, key, key_len);
	sha512_Final (&ctx_sha, hashbuf);
	memzero (&ctx_sha, sizeof(ctx_sha));

	memcpy (iv, hashbuf+(enc_count++), AES_BLOCK_SIZE/2);
	memcpy (enc_key, hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2), SHA3_256_DIGEST_LENGTH/2);
	memcpy (iv+(AES_BLOCK_SIZE/2), hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2)+(SHA3_256_DIGEST_LENGTH/2), AES_BLOCK_SIZE/2);
	memcpy (enc_key+(SHA3_256_DIGEST_LENGTH/2), hashbuf+(enc_count++)+AES_BLOCK_SIZE+(SHA3_256_DIGEST_LENGTH/2), SHA3_256_DIGEST_LENGTH/2);
	memzero (hashbuf, sizeof(hashbuf));

#if 0 //def DEBUG_TRUST_SIGNER
	hex_print (hexbuf, iv, sizeof(iv));
	LOGD("IV : %s\n", hexbuf);
	hex_print (hexbuf, enc_key, sizeof(enc_key));
	LOGD("KEY : %s\n", hexbuf);
#endif

	ret = aes_encrypt_key256 (enc_key, &ctx_aes);
	memzero (enc_key, sizeof(enc_key));
	if (ret == EXIT_SUCCESS) {
		ret = aes_cbc_encrypt (message, buffer, message_len, iv, &ctx_aes);
	}

	memzero (iv, sizeof(iv));
	memzero (&ctx_aes, sizeof(ctx_aes));

	return ret;
}

static int decryptAES256 (unsigned char *key, int key_len, unsigned char *message, int message_len, unsigned char *buffer) {
	int ret = 0;
	int enc_count = 1;

	aes_decrypt_ctx ctx_aes;
	uint8_t iv[AES_BLOCK_SIZE] ={0};
	uint8_t enc_key[SHA3_256_DIGEST_LENGTH] = {0};

	SHA512_CTX ctx_sha;
	unsigned char hashbuf[SHA3_512_DIGEST_LENGTH];

	sha512_Init (&ctx_sha);
	sha512_Update (&ctx_sha, key, key_len);
	sha512_Final (&ctx_sha, hashbuf);
	memzero (&ctx_sha, sizeof(ctx_sha));

	memcpy (iv, hashbuf+(enc_count++), AES_BLOCK_SIZE/2);
	memcpy (enc_key, hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2), SHA3_256_DIGEST_LENGTH/2);
	memcpy (iv+(AES_BLOCK_SIZE/2), hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2)+(SHA3_256_DIGEST_LENGTH/2), AES_BLOCK_SIZE/2);
	memcpy (enc_key+(SHA3_256_DIGEST_LENGTH/2), hashbuf+(enc_count++)+AES_BLOCK_SIZE+(SHA3_256_DIGEST_LENGTH/2), SHA3_256_DIGEST_LENGTH/2);
	memzero (hashbuf, sizeof(hashbuf));

#if 0 //def DEBUG_TRUST_SIGNER
	hex_print (hexbuf, iv, sizeof(iv));
	LOGD("IV : %s\n", hexbuf);
	hex_print (hexbuf, enc_key, sizeof(enc_key));
	LOGD("KEY : %s\n", hexbuf);
#endif

	ret = aes_decrypt_key256 (enc_key, &ctx_aes);
	memzero (enc_key, sizeof(enc_key));
	if (ret == EXIT_SUCCESS) {
		ret = aes_cbc_decrypt (message, buffer, message_len, iv, &ctx_aes);
	}

	memzero (iv, sizeof(iv));
	memzero (&ctx_aes, sizeof(ctx_aes));

	return ret;
}

static unsigned int getCoinType (char *coin) {
	int coinType = 0;
	if (!strncmp (coin, "BTC", 3)) {
		coinType = COIN_TYPE_BITCOIN;
	} else if (!strncmp (coin, "ETH", 3)) {
		coinType = COIN_TYPE_ETHEREUM;
	} else if (!strncmp (coin, "XLM", 3)) {
		coinType = COIN_TYPE_STELLAR;
	}
	return coinType;
}

#ifdef __ANDROID__
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBInitializeData(JNIEnv *env, jobject instance,
		jbyteArray appID_)
#else
extern "C"
unsigned char *TrustSigner_getWBInitializeData(char *app_id)
#endif
{
#ifdef __ANDROID__
	jbyteArray wb_data = NULL;

	const char *app_id = jbyteArry2char (env, appID_);
	const int  app_id_len = env->GetArrayLength (appID_);
#else
	unsigned char *wb_data = NULL;
	int app_id_len = strlen (app_id);
#endif

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
	const char *mnemonic = NULL;

	int table_length = 0;
	char *table_buffer = NULL;

	int enc_ret = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};
	int wb_length = 0;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};

#ifdef DEBUG_TRUST_SIGNER
	LOGD("appId = %s\n", app_id);
#endif

	// WB_TABLE Create /////////////////////////////////////////////////////////////////////////////
	table_length = trust_signer_create_table (&table_buffer);
	if (table_length <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! WB create table failed!\n");
#endif
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
	LOGD("WB Table length = %d\n", table_length);
#endif


	// SEED Create /////////////////////////////////////////////////////////////////////////////////
	mnemonic = generateMnemonic (BIP39_KEY_STRENGTH);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- MNEMONIC -------------------------------\n");
	LOGD("%s\n", mnemonic);
#endif

#ifdef DEBUG_TRUST_SIGNER
	unsigned char entropy[BIP39_KEY_STRENGTH/8] = {0};
	mnemonic_to_entropy (mnemonic, entropy);
	LOGD("----------------------------- ENTROPY --------------------------------\n");
	hex_print (hexbuf, entropy, sizeof(entropy));
	LOGD("%s\n", hexbuf);
	memzero (entropy, sizeof(entropy));
#endif

	generateBip39Seeed (mnemonic, seed, NULL);
	memzero ((void *) mnemonic, strlen((char *) mnemonic));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

#ifdef DEBUG_TRUST_SIGNER
	HDNode node;
	char private_key[BIP32_KEY_LENGTH*2] = {0};
	char public_key[BIP32_KEY_LENGTH*2] = {0};
	memset (&node, 0, sizeof(node));
	hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
	LOGD("----------------------------- M BTC PRIVATE --------------------------\n");
	hdnode_serialize_private (&node, 0, VERSION_PRIVATE, private_key, sizeof(private_key));
	LOGD("%s\n", private_key);
	hdnode_serialize_public (&node, 0, VERSION_PUBLIC, public_key, sizeof(public_key));
	LOGD("----------------------------- M BTC PUBLIC ---------------------------\n");
	LOGD("%s\n", public_key);
#endif

	// SEED AES Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_ret = encryptAES256 ((unsigned char *) app_id, app_id_len, seed, sizeof(seed), enc_buffer);
	memzero (seed, sizeof(seed));
	if (enc_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES encrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- AES ENC --------------------------------\n");
	hex_print (hexbuf, enc_buffer, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);

	int dec_ret = 0;
	unsigned char dec_buffer[AES256_ENCRYPT_LENGTH] = {0};
	dec_ret = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, sizeof(enc_buffer), dec_buffer);
	LOGD("----------------------------- AES DEC --------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(dec_buffer));
	LOGD("%s\n", hexbuf);
#endif

	// SEED WB Encrypt /////////////////////////////////////////////////////////////////////////////
	wb_length = trust_signer_encrypt (table_buffer, table_length, enc_buffer, sizeof(enc_buffer), wb_buffer, true);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (wb_length <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! WB encrypt failed!\n");
#endif
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB ENC ---------------------------------\n");
	hex_print (hexbuf, wb_buffer, wb_length);
	LOGD("%s\n", hexbuf);

	int dec_length = 0;
	memset (dec_buffer, 0, sizeof(dec_buffer));
	dec_length = trust_signer_encrypt (table_buffer, table_length, wb_buffer, wb_length, dec_buffer, false);
	LOGD("----------------------------- WB DEC ---------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(dec_buffer));
	LOGD("%s\n", hexbuf);
#endif

	// DATA Return /////////////////////////////////////////////////////////////////////////////////
#ifdef __ANDROID__
	wb_data = env->NewByteArray (table_length + wb_length);
	env->SetByteArrayRegion (wb_data, 0, table_length, (jbyte *) table_buffer);
	env->SetByteArrayRegion (wb_data, table_length, wb_length, (jbyte *) wb_buffer);
#else
	wb_data = (unsigned char *) malloc ((size_t) (table_length + wb_length));
	memcpy (wb_data, table_buffer, table_length);
	memcpy (wb_data+table_length, wb_buffer, wb_length);
#endif

	memzero (table_buffer, table_length);
	memzero (wb_buffer, wb_length);

	free (table_buffer);

	return (wb_data);
}

#ifdef __ANDROID__
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBPublicKey(JNIEnv *env, jobject instance,
													  jbyteArray appID_, jbyteArray wbData_,
													  jbyteArray coinSymbol_, jint hdDepth,
													  jint hdChange, jint hdIndex)
#else
extern "C"
char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index)
#endif
{
#ifdef __ANDROID__
	jbyteArray public_address = NULL;

	const char *app_id = jbyteArry2char (env, appID_);
	const unsigned char *wb_data = jbyteArry2uchar (env, wbData_);
	const char *coin_symbol = jbyteArry2char (env, coinSymbol_);
	const int  hd_depth = (int) hdDepth;
	const int  hd_change = (int) hdChange;
	const int  hd_index = (int) hdIndex;
	const int  app_id_len = env->GetArrayLength (appID_);
	const int wb_data_len = env->GetArrayLength (wbData_);
#else
	char *public_address = NULL;
	int app_id_len = strlen (app_id);
#endif

	HDNode node;
	unsigned int coin_type = 0;
	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
	char public_key[BIP32_KEY_LENGTH*2] = {0};

	int wb_length = wb_data_len - WB_TABLE_LENGTH;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	int enc_length = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};
	int dec_ret = 0;

	uint32_t fingerprint = 0;
	uint32_t bip44_path[BIP44_PATH_DEPTH_MAX] = {0};

    if (hd_depth < 3) {
#ifdef DEBUG_TRUST_SIGNER
        LOGD("Error! not support!\n");
#endif
        return NULL;
    }

    // SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
	memcpy (wb_buffer, wb_data+WB_TABLE_LENGTH, wb_length);
	enc_length = trust_signer_encrypt ((char *) wb_data, WB_TABLE_LENGTH, wb_buffer, wb_length, enc_buffer, false);
	memzero (wb_buffer, wb_length);

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	dec_ret = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_length, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (dec_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES decrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

	coin_type = getCoinType ((char *)coin_symbol);
	if (coin_type <= 0){
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! Can not find coin type!\n");
#endif
		memzero (seed, sizeof(seed));
		return NULL;
	}

	// Create HD Node //////////////////////////////////////////////////////////////////////////////
	memset (&node, 0, sizeof(node));
	switch (coin_type) {
		case COIN_TYPE_BITCOIN:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_BITCOIN | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_ETHEREUM:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_ETHEREUM | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_STELLAR:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_STELLAR | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = hd_index | BIP44_VAL_HARDENED;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, ED25519_NAME, &node);
			break;
	}
	memzero (seed, sizeof(seed));

	fingerprint = coin_derive_node (&node, bip44_path, hd_depth);
	if (fingerprint == 0xFFFFFFFF) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES decrypt failed!\n");
#endif
		memzero (&node, sizeof(node));
		return NULL;
	}

	// Get Public Addreee //////////////////////////////////////////////////////////////////////////
	// check site : https://iancoleman.io/bip39/#english
	switch (coin_type) {
		case COIN_TYPE_BITCOIN: {
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- BTC PRIVATE ----------------------------\n");
			char private_key[BIP32_KEY_LENGTH*2] = {0};
			hdnode_serialize_private (&node, fingerprint, VERSION_PRIVATE, private_key, sizeof(private_key));
			LOGD("%s\n", private_key);
#endif
			hdnode_serialize_public (&node, fingerprint, VERSION_PUBLIC, public_key, sizeof(public_key));
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- BTC PUBLIC -----------------------------\n");
			LOGD("%s\n", public_key);
#endif
			break;
		}
		case COIN_TYPE_ETHEREUM: {
			 hdnode_serialize_public (&node, fingerprint, VERSION_PUBLIC, public_key, sizeof(public_key));
#ifdef DEBUG_TRUST_SIGNER
			 LOGD("----------------------------- ETH PUBLIC -----------------------------\n");
			 LOGD("%s\n", public_key);
#endif
			 break;
		}
#if 0 // ETH Address
		{
			 uint32_t chain_id = 3;
			 uint8_t address[ETHEREUM_ADDRESS_LENGTH] = {0};
			 if (!hdnode_get_ethereum_pubkeyhash(&node, address)) {
#ifdef DEBUG_TRUST_SIGNER
				 LOGD("Error! Ethereum address check fail!\n");
#endif
			 }
			 public_key[0] = '0';
			 public_key[1] = 'x';
			 ethereum_address_checksum (address, public_key + 2, false, chain_id);
#ifdef DEBUG_TRUST_SIGNER
			 LOGD("----------------------------- ETH PUBLIC -----------------------------\n");
			 LOGD("%s\n", public_key);
#endif
			 break;
		}
#endif
		case COIN_TYPE_STELLAR: {
			stellar_publicAddressAsStr (node.public_key + 1, public_key, sizeof(public_key));
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- XLM PUBLIC -----------------------------\n");
			LOGD("%s\n", public_key);
#endif
			break;
		}
	}
	memzero (&node, sizeof(node));

#ifdef __ANDROID__
	public_address = char2JbyteArry (env, public_key, strlen (public_key));
#else
	public_address = (char *) malloc ((size_t) strlen (public_key));
	memcpy (public_address, public_key, strlen (public_key));
#endif

	return (public_address);
}

#ifdef __ANDROID__
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBSignatureData(JNIEnv *env, jobject instance,
		jbyteArray appID_, jbyteArray wbData_,
		jbyteArray coinSymbol_, jint hdDepth,
		jint hdChange, jint hdIndex,
		jbyteArray hashMessage_)
#else
extern "C"
char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message)
#endif
{
#ifdef __ANDROID__
	jbyteArray signature = NULL;

	const char *app_id = jbyteArry2char (env, appID_);
	const unsigned char *wb_data = jbyteArry2uchar (env, wbData_);
	const char *coin_symbol = jbyteArry2char (env, coinSymbol_);
	const int  hd_depth = (int) hdDepth;
	const int  hd_change = (int) hdChange;
	const int  hd_index = (int) hdIndex;
	const char *hash_message = jbyteArry2char (env, hashMessage_);
	const int  app_id_len = env->GetArrayLength (appID_);
	const int  wb_data_len = env->GetArrayLength (wbData_);
#else
	char *signature = NULL;
	int app_id_len = strlen (app_id);
#endif

	HDNode node;
	unsigned int coin_type = 0;
	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
	unsigned char sig_message[SIGN_SIGNATURE_LENGTH] = {0};

	int wb_length = wb_data_len - WB_TABLE_LENGTH;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	int enc_length = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};
	int dec_ret = 0;

	uint32_t fingerprint = 0;
	uint32_t bip44_path[BIP44_PATH_DEPTH_MAX] = {0};

    if (hd_depth < 3) {
#ifdef DEBUG_TRUST_SIGNER
        LOGD("Error! not support!\n");
#endif
        return NULL;
    }

	// SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
	memcpy (wb_buffer, wb_data+WB_TABLE_LENGTH, wb_length);
	enc_length = trust_signer_encrypt ((char *) wb_data, WB_TABLE_LENGTH, wb_buffer, wb_length, enc_buffer, false);
	memzero (wb_buffer, wb_length);

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	dec_ret = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_length, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (dec_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES decrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

	coin_type = getCoinType ((char *)coin_symbol);
	if (coin_type <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! Can not find coin type!\n");
#endif
		memzero (seed, sizeof(seed));
		return NULL;
	}

	// Create HD Node //////////////////////////////////////////////////////////////////////////////
	memset (&node, 0, sizeof(node));
	switch (coin_type) {
		case COIN_TYPE_BITCOIN:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_BITCOIN | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_ETHEREUM:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_ETHEREUM | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_STELLAR:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_STELLAR | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = hd_index | BIP44_VAL_HARDENED;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, ED25519_NAME, &node);
			break;
	}
	memzero (seed, sizeof(seed));

	fingerprint = coin_derive_node (&node, bip44_path, hd_depth);
	if (fingerprint == 0xFFFFFFFF) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES decrypt failed!\n");
#endif
		memzero (&node, sizeof(node));
		return NULL;
	}

	// Create Signature ////////////////////////////////////////////////////////////////////////////
	switch (coin_type) {
		case COIN_TYPE_BITCOIN: {
			// Hash size is 32Byte
			bitcoin_hash_sign(&node, (uint8_t *) hash_message, sig_message);
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- SIGNATURE BTC --------------------------\n");
			LOGD("HashMessage : %s\n", hash_message);
			hex_print (hexbuf, sig_message, SIGN_SIGNATURE_LENGTH);
			LOGD("Signature : %s\n", hexbuf);
#endif
			break;
		}
		case COIN_TYPE_ETHEREUM: {
			 ethereum_hash_sign(&node, (uint8_t *) hash_message, sig_message);
#ifdef DEBUG_TRUST_SIGNER
			 LOGD("----------------------------- SIGNATURE ETH --------------------------\n");
			 LOGD("HashMessage : %s\n", hash_message);
			 hex_print (hexbuf, sig_message, SIGN_SIGNATURE_LENGTH);
			 LOGD("Signature : %s\n", hexbuf);
#endif
			 break;
		}
		case COIN_TYPE_STELLAR: {
			stellar_hash_sign(&node, (uint8_t *) hash_message, sig_message);
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- SIGNATURE XLM --------------------------\n");
			LOGD("HashMessage : %s\n", hash_message);
			hex_print (hexbuf, sig_message, SIGN_SIGNATURE_LENGTH);
			LOGD("Signature : %s\n", hexbuf);
#endif
			break;
		}
	}
	memzero(&node, sizeof(node));

#ifdef __ANDROID__
	signature = uchar2JbyteArry (env, sig_message, SIGN_SIGNATURE_LENGTH);
#else
	signature = (char *) malloc (SIGN_SIGNATURE_LENGTH);
	memcpy (signature, sig_message, SIGN_SIGNATURE_LENGTH);
#endif

	return (signature);
}

#ifdef __ANDROID__
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBRecoveryData(JNIEnv *env, jobject instance,
		jbyteArray appID_, jbyteArray wbData_,
		jbyteArray userKey_, jbyteArray serverKey_)
#else
extern "C"
char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, int wb_data_len, char *user_key, int user_key_len, char *server_key, int server_key_len)
#endif
{
#ifdef __ANDROID__
	jbyteArray recovery_data = NULL;

	const char *app_id = jbyteArry2char (env, appID_);
	const char *wb_data = jbyteArry2char (env, wbData_);
	const char *user_key = jbyteArry2char (env, userKey_);
	const char *server_key = jbyteArry2char (env, serverKey_);
	const int  app_id_len = env->GetArrayLength (appID_);
	const int  wb_data_len = env->GetArrayLength (wbData_);
	const int  user_key_len = env->GetArrayLength (userKey_);
	const int  server_key_len = env->GetArrayLength (serverKey_);
#else
	char *recovery_data = NULL;
	int app_id_len = strlen (app_id);
#endif

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};

	int wb_length = wb_data_len - WB_TABLE_LENGTH;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	int enc_length = 0;
	unsigned char enc_buffer[BIP39_KEY_STRENGTH/4+RANDOM_NONCE_LENGTH] = {0};
	int enc_ret = 0;
	int dec_ret = 0;

	// SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
	memcpy (wb_buffer, wb_data+WB_TABLE_LENGTH, wb_length);
	enc_length = trust_signer_encrypt ((char *) wb_data, WB_TABLE_LENGTH, wb_buffer, wb_length, enc_buffer, false);
	memzero (wb_buffer, wb_length);

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	dec_ret = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_length, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (dec_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES decrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

	uint8_t iv_random[16] = {0};
	uint8_t nonce[RANDOM_NONCE_LENGTH] = {0};
	random_buffer (nonce, RANDOM_NONCE_LENGTH);

	char *base64_recovery_iv = NULL;
	random_buffer (iv_random, sizeof(iv_random));
	base64_recovery_iv = base64_encode ((char *) iv_random, sizeof(iv_random));

	unsigned char org_recovery[BIP39_KEY_STRENGTH/4+RANDOM_NONCE_LENGTH] = {0};
	memcpy (org_recovery, nonce, RANDOM_NONCE_LENGTH/2);
	memcpy (org_recovery+RANDOM_NONCE_LENGTH/2, seed, sizeof(seed));
	memcpy (org_recovery+RANDOM_NONCE_LENGTH/2+BIP39_KEY_STRENGTH/4, nonce+RANDOM_NONCE_LENGTH/2, RANDOM_NONCE_LENGTH/2);

	memzero (seed, sizeof(seed));
	memzero (nonce, sizeof(nonce));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- ORG RECOVERY ---------------------------\n");
	hex_print (hexbuf, org_recovery, sizeof(org_recovery));
	LOGD("%s\n", hexbuf);
#endif

	// SEED AES User Key Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_ret = encryptAES256 ((unsigned char *) user_key, user_key_len, org_recovery, sizeof(org_recovery), enc_buffer);
	memzero (org_recovery, sizeof(org_recovery));
	if (enc_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES encrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- AES ENC --------------------------------\n");
	hex_print (hexbuf, enc_buffer, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);

	unsigned char dec_buffer[BIP39_KEY_STRENGTH/4+RANDOM_NONCE_LENGTH] = {0};
	dec_ret = decryptAES256 ((unsigned char *) user_key, user_key_len, enc_buffer, sizeof(enc_buffer), dec_buffer);
	LOGD("----------------------------- AES DEC --------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(dec_buffer));
	LOGD("%s\n", hexbuf);
#endif

	char *base64_recovery = NULL;
	base64_recovery = base64_encode ((char *) enc_buffer, sizeof(enc_buffer));
	memzero (enc_buffer, sizeof(enc_buffer));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("%s\n", base64_recovery);

	char *base64_recovery_de = NULL;
	base64_recovery_de = base64_decode (base64_recovery);
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, (unsigned char *) base64_recovery_de, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);

	memset (dec_buffer, 0, sizeof(dec_buffer));
	dec_ret = decryptAES256 ((unsigned char *) user_key, user_key_len, (unsigned char *) base64_recovery_de, sizeof(enc_buffer), dec_buffer);
	free (base64_recovery_de);
	LOGD("----------------------------- AES DEC --------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(org_recovery));
	LOGD("%s\n", hexbuf);

	memcpy (seed, dec_buffer+RANDOM_NONCE_LENGTH/2, sizeof(seed));
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

	char *base64_userkey_iv = NULL;
	random_buffer (iv_random, sizeof(iv_random));
	base64_userkey_iv = base64_encode ((char *) iv_random, sizeof(iv_random));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- USER KEY -------------------------------\n");
	hex_print (hexbuf, (unsigned char *) user_key, user_key_len);
	LOGD("%s\n", hexbuf);
#endif

	unsigned char org_userkey[AES256_ENCRYPT_LENGTH+RANDOM_NONCE_LENGTH] = {0};
	random_buffer (nonce, RANDOM_NONCE_LENGTH);
	memcpy (org_userkey, nonce, RANDOM_NONCE_LENGTH/2);
	memcpy (org_userkey+RANDOM_NONCE_LENGTH/2, (unsigned char *) user_key, user_key_len);
	memcpy (org_userkey+RANDOM_NONCE_LENGTH/2+user_key_len, nonce+RANDOM_NONCE_LENGTH/2, RANDOM_NONCE_LENGTH/2);

	memzero (seed, sizeof(seed));
	memzero (nonce, sizeof(nonce));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- USER KEY ENC ---------------------------\n");
	hex_print (hexbuf, org_userkey, sizeof(org_userkey));
	LOGD("%s\n", hexbuf);
#endif

	// User Key AES Server Key Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_ret = encryptAES256 ((unsigned char *) server_key, server_key_len, org_userkey, sizeof(org_userkey), enc_buffer);
	memzero (org_userkey, sizeof(org_userkey));
	if (enc_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES encrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- ENC USER KEY ---------------------------\n");
	hex_print (hexbuf, enc_buffer, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);
#endif

	char *base64_userkey = NULL;
	base64_userkey = base64_encode ((char *) enc_buffer, sizeof(enc_buffer));
	memzero (enc_buffer, sizeof(enc_buffer));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("%s\n", base64_userkey);

	char *base64_userkey_de = NULL;
	base64_userkey_de = base64_decode (base64_userkey);
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, (unsigned char *) base64_userkey_de, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);

	memset (dec_buffer, 0, sizeof(dec_buffer));
	dec_ret = decryptAES256 ((unsigned char *) server_key, server_key_len, (unsigned char *) base64_userkey_de, sizeof(enc_buffer), dec_buffer);
	free (base64_userkey_de);
	LOGD("----------------------------- DEC USER KEY ---------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(org_recovery));
	LOGD("%s\n", hexbuf);

	char userkey[64] = {0};
	memcpy (userkey, dec_buffer+RANDOM_NONCE_LENGTH/2, sizeof(userkey));
	LOGD("----------------------------- USER KEY -------------------------------\n");
	hex_print (hexbuf, (unsigned char *) userkey, sizeof(userkey));
	LOGD("%s\n", hexbuf);
#endif

	char recovery_buffer[RECOVERY_BUFFER_LENGTH] = {0};
    sprintf (recovery_buffer, "{\"iv\":\"%s\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"%s\"},{\"iv\":\"%s\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"%s\"}", base64_recovery_iv, base64_recovery, base64_userkey_iv, base64_userkey);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- RECOVERY DATA --------------------------\n");
	LOGD("%s\n", recovery_buffer);
#endif

	memzero (base64_recovery, strlen(base64_recovery));
	free (base64_recovery_iv);
	free (base64_recovery);

	memzero (base64_userkey, strlen(base64_userkey));
	free (base64_userkey_iv);
	free (base64_userkey);

#ifdef __ANDROID__
	recovery_data = char2JbyteArry (env, recovery_buffer, strlen (recovery_buffer));
#else
	recovery_data = (char *) malloc ((size_t) strlen (recovery_buffer));
	memcpy (recovery_data, recovery_buffer, strlen (recovery_buffer));
#endif

	memzero (recovery_buffer, sizeof(recovery_buffer));

    return (recovery_data);
}

#ifdef __ANDROID__
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_setWBRecoveryData(JNIEnv *env, jobject instance,
		jbyteArray appID_,
		jbyteArray userKey_,
		jbyteArray recoveryData_)
#else
extern "C"
unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, int user_key_len, char *recovery_data, int recovery_data_len)
#endif
{
#ifdef __ANDROID__
    jbyteArray wb_data = NULL;

    const char *app_id = jbyteArry2char (env, appID_);
	const char *user_key = jbyteArry2char (env, userKey_);
	const char *recovery_data = jbyteArry2char (env, recoveryData_);
    const int  app_id_len = env->GetArrayLength (appID_);
	const int  user_key_len = env->GetArrayLength (userKey_);
	const int  recovery_data_len = env->GetArrayLength (recoveryData_);
#else
	unsigned char *wb_data = NULL;
	int app_id_len = strlen (app_id);
#endif

	int table_length = 0;
	char *table_buffer = NULL;
	int wb_length = 0;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};

	int enc_ret = 0;
	int dec_ret = 0;
	char base64_recovery[TEMP_BUFFER_LENGTH] = {0};
	char *base64_recovery_de = NULL;
	unsigned char dec_recovery[BIP39_KEY_STRENGTH/4+RANDOM_NONCE_LENGTH] = {0};

	strncpy (base64_recovery, recovery_data+(recovery_data_len-(128)-2), 128);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("%s\n", base64_recovery);
#endif

	base64_recovery_de = base64_decode (base64_recovery);
	memzero (base64_recovery, sizeof(base64_recovery));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, (unsigned char *) base64_recovery_de, sizeof(dec_recovery));
	LOGD("%s\n", hexbuf);
#endif

	dec_ret = decryptAES256 ((unsigned char *) user_key, user_key_len, (unsigned char *) base64_recovery_de, sizeof(dec_recovery), dec_recovery);
	memzero (base64_recovery_de, strlen(base64_recovery_de));
	free (base64_recovery_de);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- AES DEC --------------------------------\n");
	hex_print (hexbuf, dec_recovery, sizeof(dec_recovery));
	LOGD("%s\n", hexbuf);
#endif

	memcpy (seed, dec_recovery+RANDOM_NONCE_LENGTH/2, sizeof(seed));
	memzero (dec_recovery, sizeof(dec_recovery));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("%s\n", hexbuf);
#endif

	// WB_TABLE Create /////////////////////////////////////////////////////////////////////////////
	table_length = trust_signer_create_table (&table_buffer);
	if (table_length <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! WB create table failed!\n");
#endif
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
	LOGD("WB Table length = %d\n", table_length);
#endif

	// SEED AES Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_ret = encryptAES256 ((unsigned char *) app_id, app_id_len, seed, sizeof(seed), enc_buffer);
	memzero (seed, sizeof(seed));
	if (enc_ret != EXIT_SUCCESS) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! AES encrypt failed!\n");
#endif
		return NULL;
	}

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- AES ENC --------------------------------\n");
	hex_print (hexbuf, enc_buffer, sizeof(enc_buffer));
	LOGD("%s\n", hexbuf);

	unsigned char dec_buffer[AES256_ENCRYPT_LENGTH] = {0};
	dec_ret = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, sizeof(enc_buffer), dec_buffer);
	LOGD("----------------------------- AES DEC --------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(dec_buffer));
	LOGD("%s\n", hexbuf);
#endif

	// SEED WB Encrypt /////////////////////////////////////////////////////////////////////////////
	wb_length = trust_signer_encrypt (table_buffer, table_length, enc_buffer, sizeof(enc_buffer), wb_buffer, true);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (wb_length <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGD("Error! WB encrypt failed!\n");
#endif
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB ENC ---------------------------------\n");
	hex_print (hexbuf, wb_buffer, wb_length);
	LOGD("%s\n", hexbuf);

	int dec_length = 0;
	memset (dec_buffer, 0, sizeof(dec_buffer));
	dec_length = trust_signer_encrypt (table_buffer, table_length, wb_buffer, wb_length, dec_buffer, false);
	LOGD("----------------------------- WB DEC ---------------------------------\n");
	hex_print (hexbuf, dec_buffer, sizeof(dec_buffer));
	LOGD("%s\n", hexbuf);
#endif

	// DATA Return /////////////////////////////////////////////////////////////////////////////////
#ifdef __ANDROID__
	wb_data = env->NewByteArray (table_length + wb_length);
	env->SetByteArrayRegion (wb_data, 0, table_length, (jbyte *) table_buffer);
	env->SetByteArrayRegion (wb_data, table_length, wb_length, (jbyte *) wb_buffer);
#else
	wb_data = (unsigned char *) malloc ((size_t) (table_length + wb_length));
	memcpy (wb_data, table_buffer, table_length);
	memcpy (wb_data+table_length, wb_buffer, wb_length);
#endif

	memzero (table_buffer, table_length);
	memzero (wb_buffer, wb_length);

	free (table_buffer);

	return (wb_data);
}

#ifdef __ANDROID__
static const char *SIGN = "308201dd30820146020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b3009060355040613025553301e170d3138313231313031353132355a170d3438313230333031353132355a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330819f300d06092a864886f70d010101050003818d0030818902818100ed259fb16fcc3c21b7b5ce14f3535e221357a800438863eda3671e4a098b52b8f4e966175f84e7b87d5e24211db4f47e2bfbec25c26fb3a5934fd5595df7df495a56a25361782d64983ba7d9f9d6ef50d62f21414eb5e1fc9cd77f8f36d0306b33d55a33ce261559cdb05bb30bf8bc4bd8341a485686f3e7ba6d50a923d2478b0203010001300d06092a864886f70d01010505000381810004255f6af67200e91f8fc345f6e383f23d3e7542dba4bc63747d524a70c640a9f40de0f097c510f8cda222eafb33e5890f444d657c028e68fbb49c91ed27e15bc9c4c794ff71a26f59e28897b110e3e2ff697702f464a0bd0d19eef39b79d1659f54ecdfbb9906db93bc08b99bfe41d60df2faa6592e30e518a3849af5679c30";

static int verifySign(JNIEnv *env);

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
	JNIEnv *env = NULL;
	if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
		return JNI_ERR;
	}
	if (verifySign(env) == JNI_OK) {
		return JNI_VERSION_1_4;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGE("Error! Unmatched signatures!");
#endif
	return JNI_ERR;
}

static jobject getApplication(JNIEnv *env) {
	jobject application = NULL;
	jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
	if (activity_thread_clz != NULL) {
		jmethodID currentApplication = env->GetStaticMethodID(
				activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
		if (currentApplication != NULL) {
			application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
		} else {
#ifdef DEBUG_TRUST_SIGNER
			LOGE("Cannot find method: currentApplication() in ActivityThread.");
#endif
		}
		env->DeleteLocalRef(activity_thread_clz);
	} else {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Cannot find class: android.app.ActivityThread");
#endif
	}

	return application;
}

static int verifySign(JNIEnv *env) {
	// Application object
	jobject application = getApplication(env);
	if (application == NULL) {
		return JNI_ERR;
	}
	// Context(ContextWrapper) class
	jclass context_clz = env->GetObjectClass(application);
	// getPackageManager()
	jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
												   "()Landroid/content/pm/PackageManager;");
	// android.content.pm.PackageManager object
	jobject package_manager = env->CallObjectMethod(application, getPackageManager);
	// PackageManager class
	jclass package_manager_clz = env->GetObjectClass(package_manager);
	// getPackageInfo()
	jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
												"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
	// context.getPackageName()
	jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
												"()Ljava/lang/String;");
	// call getPackageName() and cast from jobject to jstring
	jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
	// PackageInfo object
	jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, package_name, 64);
	// class PackageInfo
	jclass package_info_clz = env->GetObjectClass(package_info);
	// field signatures
	jfieldID signatures_field = env->GetFieldID(package_info_clz, "signatures",
												"[Landroid/content/pm/Signature;");
	jobject signatures = env->GetObjectField(package_info, signatures_field);
	jobjectArray signatures_array = (jobjectArray) signatures;
	jobject signature0 = env->GetObjectArrayElement(signatures_array, 0);
	jclass signature_clz = env->GetObjectClass(signature0);

	jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString",
											   "()Ljava/lang/String;");
	// call toCharsString()
	jstring signature_str = (jstring) (env->CallObjectMethod(signature0, toCharsString));

	// release
	env->DeleteLocalRef(application);
	env->DeleteLocalRef(context_clz);
	env->DeleteLocalRef(package_manager);
	env->DeleteLocalRef(package_manager_clz);
	env->DeleteLocalRef(package_name);
	env->DeleteLocalRef(package_info);
	env->DeleteLocalRef(package_info_clz);
	env->DeleteLocalRef(signatures);
	env->DeleteLocalRef(signature0);
	env->DeleteLocalRef(signature_clz);

	const char *sign = env->GetStringUTFChars(signature_str, NULL);
	if (sign == NULL) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! Failed to allocate memory!");
#endif
		return JNI_ERR;
	}

#ifdef DEBUG_TRUST_SIGNER
    LOGD("### MYSEO : App Sign   ：%s", sign);
    LOGD("### MYSEO : Native Sign：%s", SIGN);
#endif
	int result = strcmp(sign, SIGN);

	// Release this memory after use
	env->ReleaseStringUTFChars(signature_str, sign);
	env->DeleteLocalRef(signature_str);
	if (result == 0) {
		return JNI_OK;
	}
	return JNI_ERR;
}

extern "C"
JNIEXPORT void JNICALL
Java_io_talken_trustsigner_TrustSigner_test1(JNIEnv *env, jobject instance) {

}
#endif
