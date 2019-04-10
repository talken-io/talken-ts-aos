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
	char *user_key = "553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0";
	char *server_key = "71db7cb1bcfa049c2878f1cf0c34fd3a3b87d68e8e6c1a7a7971bdf3b00b822a5ad846cca500ced86b94b8c37a3ac879a8994005d89ef30d9ae837344c1725b0";
	unsigned char *wb_data = NULL;
	char *public_key = NULL;
	unsigned char *signature = NULL;
	char *recovery_data = "{\"iv\":\"p2gvnNR3Wh/wTZIVXxjJ/Q==\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"bZHz6C17q2fk7Dfd1T6POVXwp+hTq6qSd5x5SpM3RCpkQZhjf2eEDgtTsWMCzlfu23GalqgyuG8w0hoD4SXVASdL3xq51SWLbgZT3Fb2VP1Bd/shDFNJKoMKJQAxHiS+Qegps0qPRuOAUYKC1W9OlKxZGhlPp0z1Ja/bM0/8tm9iQffGT/enYchPIIn4aMh3RfEG0D1sh5xj9QEjiMYBnA==\"}";

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
	TrustSigner_getWBRecoveryData(app_id, FILE_PATH, user_key, server_key);
#else
	TrustSigner_getWBRecoveryData(app_id, wb_data, user_key, server_key);
#endif

	free (wb_data);
	wb_data = NULL;

#if defined(__FILES__)
	wb_data = TrustSigner_setWBRecoveryData(app_id, FILE_PATH, user_key, recovery_data);
#else
	wb_data = TrustSigner_setWBRecoveryData(app_id, user_key, recovery_data);
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
