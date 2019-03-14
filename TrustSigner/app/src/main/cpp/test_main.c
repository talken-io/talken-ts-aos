#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "whitebox.h"
#include "bip32_bip39.h"

extern unsigned char *TrustSigner_getWBInitializeData(char *app_id);
extern char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_table_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
extern char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_table_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len);
extern char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, int wb_table_len, char *user_key, int user_key_len, char *server_key, int server_key_len);
extern unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, int user_key_len, char *recovery_data, int recovery_data_len);

int main (void) {
	char *app_id = "123-456-789-012-345-678-900";
	char *message = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
	char *message_btc = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
	//char *message_btc = "471e8de7fc2e1e3237dfde94d66ee7fb948f340f0bb54d868985062ccd4d9032";
	char *key = "1234567890123456789012345678901234567890123456789012345678901234";
	unsigned char *wb_data = NULL;
	char *public_key = NULL;
	char *signature = NULL;
	char *recovery_data = NULL;

	wb_data = TrustSigner_getWBInitializeData (app_id);
    
	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "BTC", 5, 0, 0);
	free (public_key);

	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "ETH", 5, 0, 0);
	free (public_key);

	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "XLM", 3, 0, 0);
	free (public_key);

    unsigned char *hashMessage_btc = (unsigned char *) str2hex (message_btc, strlen(message_btc));
	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "BTC", 5, 0, 0, hashMessage_btc, strlen(message_btc)/2);
	free (signature);

    unsigned char *hashMessage = (unsigned char *) str2hex (message, strlen(message));
	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "ETH", 5, 0, 0, hashMessage, strlen(message)/2);
	free (signature);

	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "XLM", 3, 0, 0, hashMessage, strlen(message)/2);
	free (signature);

	recovery_data = TrustSigner_getWBRecoveryData(app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, key, strlen(key), key, strlen(key));

	free (wb_data);
	wb_data = NULL;

	wb_data = TrustSigner_setWBRecoveryData(app_id, key, strlen(key), recovery_data, 240);

	free (recovery_data);

	free (wb_data);

	return 0;
}
