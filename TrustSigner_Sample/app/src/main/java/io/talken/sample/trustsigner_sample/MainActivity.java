package io.talken.sample.trustsigner_sample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.talken.trustsigner.TrustSigner;

public class MainActivity extends AppCompatActivity {

    TrustSigner mTrustSigner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mTrustSigner = new TrustSigner(this,"myseo_test_app");

        findViewById(R.id.btn_get_initialize_data).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getInitializeData();
            }
        });

        findViewById(R.id.btn_get_signature_data).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getSignatureData();
            }
        });

        findViewById(R.id.btn_get_recovery_data).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getRecoveryData();
            }
        });

        findViewById(R.id.btn_set_recovery_data).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setRecoveryData();
            }
        });
    }

    private void getInitializeData() {
        mTrustSigner.initialize();
    }

    private void getSignatureData() {
        String pubKey = null;
        String btcHash = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
        String hashMsg = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c";
        String sigMsg = null;

        mTrustSigner.initialize();

        pubKey = mTrustSigner.getAccountPublicKey("BTC");
        System.out.println("@@@ TrustSigner : BTC Pub Key = " + pubKey);
        pubKey = mTrustSigner.getAccountPublicKey("ETH");
        System.out.println("@@@ TrustSigner : ETH Pub Key = " + pubKey);
        pubKey = mTrustSigner.getAccountPublicKey("XLM");
        System.out.println("@@@ TrustSigner : XLM Pub Key = " + pubKey);

//        pubKey = mTrustSigner.getPublicKey("BTC", 4, 0, 0);
//        System.out.println("@@@ TrustSigner : BTC (m/44'/0'/0) Pub Key = " + pubKey);

        sigMsg = mTrustSigner.getSignatureData("BTC", 5, 0, 0, btcHash);
        System.out.println("@@@ TrustSigner : BTC Sig = " + sigMsg);
        sigMsg = mTrustSigner.getSignatureData("ETH", 5, 0, 0, hashMsg);
        System.out.println("@@@ TrustSigner : ETH Sig = " + sigMsg);
        sigMsg = mTrustSigner.getSignatureData("XLM", 3, 0, 0, hashMsg);
        System.out.println("@@@ TrustSigner : XLM Sig = " + sigMsg);
    }

    private void getRecoveryData() {
        String recoveryData = null;
        String userKey = SHA512("admin123!!!");
        String ServerKey = SHA512("124124123412414214124");

        System.out.println("@@@ TrustSigner : " + userKey + " , " + ServerKey);

        mTrustSigner.initialize();

        recoveryData = mTrustSigner.getRecoveryData(userKey, ServerKey);
        System.out.println("@@@ TrustSigner : Recovery Data = " + recoveryData);
    }

    private void setRecoveryData() {
        String pubKey = null;
        String org_recoveryData = "{\"iv\":\"p2gvnNR3Wh/wTZIVXxjJ/Q==\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"xDqFqIr/0HS2aTNR/S69flmreTGDIukhqc7SVLMTN1Ebe3vImU+uXuCg8WJVyHV7L8/sFc8JiWUl7yyZFbyymHQE7uhzB63Pobe03vaVGAolX0gpUr7vy8Ph92APKa4VjRgbNlcJYr/ax1MHFGlStuPi5/wBSWPmgxNEI6tf2sMkJxRsF4vilif+jv5/x/avkv193J5yiERjdDH03N9rsg==\"}";
        String userKey = "553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0";

        if (mTrustSigner.setRecoveryData(userKey, org_recoveryData) != true) {
            System.out.println("@@@ TrustSigner : Error! Recovery Failed.");
        }

        mTrustSigner.initialize();
        pubKey = mTrustSigner.getAccountPublicKey("BTC");
        System.out.println("@@@ TrustSigner : BTC Pub Key = " + pubKey);

        System.out.println("ORG =================================================\n");
        System.out.println("neither way city bird steak bubble clown enjoy media palm flash give figure consider october display dragon edit razor unfold step traffic salt say\n");
        System.out.println("d13b1c3c54fef76da1457676cf29341dbc4c6369f0c72dd3a63f32293206891875e153da8f7bc434d68fcb82d07e934c34a9fa427fd4edbafecea5c9da587fe6\\n");
    }

    public static String SHA512(String org) {
        String SHA512 = "";
        try {
            MessageDigest sh = MessageDigest.getInstance("SHA-512");

            sh.update(org.getBytes());
            byte byteData[] = sh.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            SHA512 = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            SHA512 = null;
        }
        return SHA512;
    }
}
