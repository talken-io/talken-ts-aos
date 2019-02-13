#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "whitebox.h"

extern unsigned char *TrustSigner_getWBInitializeData(char *app_id);
extern char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
extern char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message);
extern char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, int wb_data_len, char *user_key, int user_key_len, char *server_key, int server_key_len);
extern unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, int user_key_len, char *recovery_data, int recovery_data_len);

int main (void) {
	char *app_id = "123-456-789-012-345-678-900";
	char *message = "1234567890123456789012";
	char *key = "1234567890123456789012345678901234567890123456789012345678901234";
	unsigned char *wb_data = NULL;
	char *public_address = NULL;
	char *signature = NULL;
	char *recovery_data = NULL;

	wb_data = TrustSigner_getWBInitializeData (app_id);

	public_address = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "BTC", 3, 0, 0);
	free (public_address);

	public_address = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "ETH", 3, 0, 0);
	free (public_address);

	public_address = TrustSigner_getWBPublicKey (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "XLM", 3, 0, 0);
	free (public_address);

	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "BTC", 3, 0, 0, message);
	free (signature);

	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "ETH", 3, 0, 0, message);
	free (signature);

	signature = TrustSigner_getWBSignatureData (app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, "XLM", 3, 0, 0, message);
	free (signature);

	recovery_data = TrustSigner_getWBRecoveryData(app_id, wb_data, WB_TABLE_LENGTH+WB_ENCDATA_LENGTH, key, strlen(key), key, strlen(key));

	free (wb_data);
	wb_data = NULL;

	wb_data = TrustSigner_setWBRecoveryData(app_id, key, strlen(key), recovery_data, 240);

	free (recovery_data);

	free (wb_data);

	return 0;
}
