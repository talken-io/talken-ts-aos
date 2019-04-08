#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "trustsigner.h"
#include "whitebox.h"
#include "bip32_bip39.h"

#define FILE_PATH "/Users/myseo/AndroidStudioProjects/Talken/TrustSigner/app/src/main/cpp"

int main (void) {
	char *app_id = "123-456-789-012-345-678-900";
	char *message = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
	char *message_btc = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
//	char *message_btc = "775b5767a4ce1a902b2464de95dc55c7b1c11e4ee701b27d59cce4ed4924d0a89340860d0484bd140834fdff014d99db0cefd0241855101bc02d73dd032941c6";
//	char *message_btc = "471e8de7fc2e1e3237dfde94d66ee7fb948f340f0bb54d868985062ccd4d9032";
	char *key = "1234567890123456789012345678901234567890123456789012345678901234";
	unsigned char *wb_data = NULL;
	char *public_key = NULL;
	unsigned char *signature = NULL;
	char *recovery_data = "{\"iv\":\"LfxbVm5wfdVsOZ3Wcf/EJS9Vc2Vycy9t\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"bZHz6C17q2fk7Dfd1T6POVXwp+hTq6qSd5x5SpM3RCpkQZhjf2eEDgtTsWMCzlfu23GalqgyuG8w0hoD4SXVASdL3xq51SWLbgZT3Fb2VP1Bd/shDFNJKoMKJQAxHiS+Qegps0qPRuOAUYKC1W9OlKxZGhlPp0z1Ja/bM0/8tm9iQffGT/enYchPIIn4aMh3RfEG0D1sh5xj9QEjiMYBnA==\"}";

#if defined(__FILES__)
	wb_data = TrustSigner_getWBInitializeData (app_id, FILE_PATH);
#else
	wb_data = TrustSigner_getWBInitializeData (app_id);
#endif

#if defined(__FILES__)
	public_key = TrustSigner_getWBPublicKey (app_id, FILE_PATH, wb_data, "BTC", 5, 0, 0);
#else
	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, "BTC", 5, 0, 0);
#endif
	free (public_key);

#if defined(__FILES__)
	public_key = TrustSigner_getWBPublicKey (app_id, FILE_PATH, wb_data, "ETH", 5, 0, 0);
#else
	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, "ETH", 5, 0, 0);
#endif
	free (public_key);

#if defined(__FILES__)
	public_key = TrustSigner_getWBPublicKey (app_id, FILE_PATH, wb_data, "XLM", 3, 0, 0);
#else
	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, "XLM", 3, 0, 0);
#endif
	free (public_key);

	unsigned char *hashMessage_btc = (unsigned char *) str2hex (message_btc, strlen(message_btc));
#if defined(__FILES__)
	signature = TrustSigner_getWBSignatureData (app_id, FILE_PATH, wb_data, "BTC", 5, 0, 0, hashMessage_btc, strlen(message_btc)/2);
#else
	signature = TrustSigner_getWBSignatureData (app_id, wb_data, "BTC", 5, 0, 0, hashMessage_btc, strlen(message_btc)/2);
#endif
	free (signature);

	unsigned char *hashMessage = (unsigned char *) str2hex (message, strlen(message));
#if defined(__FILES__)
	signature = TrustSigner_getWBSignatureData (app_id, FILE_PATH, wb_data, "ETH", 5, 0, 0, hashMessage, strlen(message)/2);
#else
	signature = TrustSigner_getWBSignatureData (app_id, wb_data, "ETH", 5, 0, 0, hashMessage, strlen(message)/2);
#endif
	free (signature);

#if defined(__FILES__)
	signature = TrustSigner_getWBSignatureData (app_id, FILE_PATH, wb_data, "XLM", 3, 0, 0, hashMessage, strlen(message)/2);
#else
	signature = TrustSigner_getWBSignatureData (app_id, wb_data, "XLM", 3, 0, 0, hashMessage, strlen(message)/2);
#endif
	free (signature);

#if defined(__FILES__)
	TrustSigner_getWBRecoveryData(app_id, FILE_PATH, key, key);
#else
	TrustSigner_getWBRecoveryData(app_id, wb_data, key, key);
#endif

	free (wb_data);
	wb_data = NULL;

#if defined(__FILES__)
	wb_data = TrustSigner_setWBRecoveryData(app_id, FILE_PATH, key, recovery_data);
#else
	wb_data = TrustSigner_setWBRecoveryData(app_id, key, recovery_data);
#endif

#if defined(__FILES__)
	public_key = TrustSigner_getWBPublicKey (app_id, FILE_PATH, wb_data, "BTC", 3, 0, 0);
#else
	public_key = TrustSigner_getWBPublicKey (app_id, wb_data, "BTC", 3, 0, 0);
#endif
	free (public_key);

	free (wb_data);

	printf ("----------------------------- ORG SEED -------------------------------\n");
	printf ("frozen caught cushion admit rough shaft future canal quality chalk stick never custom beef captain bargain happy impulse execute excite bid lend cupboard bonus\n");
	printf ("c2d8377518fc0d6664857ce1d84c7e0955cb7b9e9eae6d82b7ca13595401d6470439e924b2cf83cca6bfc6296d9c9130962d436b760ae688cfc6608e20e0e8b4\n");

	return 0;
}
