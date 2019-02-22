package io.talken.trustsigner;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import android.content.Context;
import android.text.TextUtils;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class TrustSigner {

    static {
        System.loadLibrary("trustsigner");
    }

    public static final String version = "0.9.2";
    private static final String PREF_KEY_WB = "io.talken.trustsigner.wb";

    private Context mContext;
    private byte[] mAppID = null;
    private byte[] mWbData = null;

    private native byte[] getWBInitializeData (byte[] appID);
    private native byte[] getWBPublicKey      (byte[] appID, byte[] wbData, byte[] coinSymbol, int hdDepth, int hdChange, int hdIndex);
    private native byte[] getWBSignatureData  (byte[] appID, byte[] wbData, byte[] coinSymbol, int hdDepth, int hdChange, int hdIndex, byte[] hashMessage);
    private native byte[] getWBRecoveryData   (byte[] appID, byte[] wbData, byte[] userKey, byte[] serverKey);
    private native byte[] setWBRecoveryData   (byte[] appID, byte[] userKey, byte[] recoveryData);

    private native void test1 ();

    private static String getSignJava(Context context) {
        String sign = "";
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signatures = pi.signatures;
            Signature signature0 = signatures[0];
            sign = signature0.toCharsString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sign;
    }

    private static String getSystemProperty(String name) throws Exception {
        Class sysProp = Class.forName("android.os.SystemProperties");
        return (String) sysProp.getMethod("get", new Class[]{String.class}).invoke(sysProp, new Object[]{name});
    }

    private static boolean checkEmulator() {
        try {
            boolean goldfish = getSystemProperty("ro.hardware").contains("goldfish");
            boolean emu = getSystemProperty("ro.kernel.qemu").length() > 0;
            boolean sdk = getSystemProperty("ro.product.model").contains("sdk");
            if (emu || goldfish || sdk) {
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static boolean checkDebuggable(Context context){
        return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private void putStringSharedPreference (String key, String value) {
        SharedPreferences prefs =
                PreferenceManager.getDefaultSharedPreferences(mContext);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(key, value);
        editor.commit();
    }

    private String getStringSharedPreference (String key, String defValue) {
        SharedPreferences prefs =
                PreferenceManager.getDefaultSharedPreferences(mContext);
        return prefs.getString(key, defValue);
    }

    public TrustSigner (Context context, String appID) {
        mContext = context;
        mAppID = appID.getBytes();
        System.out.println("### MYSEO : sign = " + getSignJava(context));
    }

    public void initialize () {
        //저장된 WB데이터가 있는지 체크
        System.out.println("### MYSEO : TIME CHECK #1");
        String strWbData = getStringSharedPreference(PREF_KEY_WB, "");

        System.out.println("### MYSEO : TIME CHECK #2");
        if(TextUtils.isEmpty(strWbData)) {
            //WB데이터생성
            mWbData = getWBInitializeData(mAppID);

            System.out.println("### MYSEO : TIME CHECK #3");
            putStringSharedPreference(PREF_KEY_WB, byteArrayToHexString(mWbData));

            System.out.println("### MYSEO : TIME CHECK #4");
        }else {
            mWbData = hexStringToByteArray(strWbData);
        }
    }

    public void finalize() {
        Arrays.fill(mAppID, (byte) 0xFF);
        Arrays.fill(mAppID, (byte) 0x55);
        Arrays.fill(mAppID, (byte) 0x00);

        Arrays.fill(mWbData, (byte) 0xFF);
        Arrays.fill(mWbData, (byte) 0x55);
        Arrays.fill(mWbData, (byte) 0x00);
    }

    public String getPublicKey (String coinSym, int hdDepth, int hdChange, int hdIndex) {
        if (mAppID == null) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        }
        if (mWbData == null) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        }
        if (coinSym == null) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        }
        if (hdDepth < 3 || hdDepth > 5) {
            System.out.println("[TrustSigner] : HD depth value invaild! (3 ~ 5)");
            return null;
        }
        if (coinSym == "XLM" && hdDepth != 3) {
            System.out.println("[TrustSigner] : XLM HD depth value invaild! (3)");
            return null;
        }
        if (hdChange < 0 || hdChange > 1) {
            System.out.println("[TrustSigner] : HD change value invaild! (0 ~ 1)");
            return null;
        }
        if (hdIndex < 0) {
            System.out.println("[TrustSigner] : HD index value invaild!");
            return null;
        }
        byte[] pubAddr = getWBPublicKey (mAppID, mWbData, coinSym.getBytes(), hdDepth, hdChange, hdIndex);
        String publicAddress = null;
        try {
            publicAddress = new String(pubAddr, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return publicAddress;
    }

    public String getAccountPublicKey (String coinSym) {
        if (mAppID == null) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        }
        if (mWbData == null) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        }
        if (coinSym == null) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        }
        byte[] pubAddr = getWBPublicKey (mAppID, mWbData, coinSym.getBytes(), 3, 0, 0);
        String publicAddress = null;
        try {
            publicAddress = new String(pubAddr, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return publicAddress;
    }

    public String getSignatureData (String coinSym, int hdDepth, int hdChange, int hdIndex, String hashMessage) {
        if (mAppID == null) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        }
        if (mWbData == null) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        }
        if (coinSym == null) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        }
        if (hdDepth < 3 || hdDepth > 5) {
            System.out.println("[TrustSigner] : HD depth value invaild! (3 ~ 5)");
            return null;
        }
        if (coinSym == "XLM" && hdDepth != 3) {
            System.out.println("[TrustSigner] : XLM HD depth value invaild! (3)");
            return null;
        }
        if (hdChange < 0 || hdChange > 1) {
            System.out.println("[TrustSigner] : HD change value invaild! (0 ~ 1)");
            return null;
        }
        if (hdIndex < 0) {
            System.out.println("[TrustSigner] : HD index value invaild!");
            return null;
        }
        if (hashMessage == null) {
            System.out.println("[TrustSigner] : Hash message is empty!");
            return null;
        }
        byte[] signature = getWBSignatureData (mAppID, mWbData, coinSym.getBytes(), hdDepth, hdChange, hdIndex, hexStringToByteArray(hashMessage));
        return byteArrayToHexString(signature);
    }

    public String getRecoveryData (String userKey, String serverKey) {
        if (mAppID == null) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        }
        if (mWbData == null) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        }
        if (userKey == null) {
            System.out.println("[TrustSigner] : User key is empty!");
            return null;
        }
        if (serverKey == null) {
            System.out.println("[TrustSigner] : Server key is empty!");
            return null;
        }
        byte[] recovData = getWBRecoveryData (mAppID, mWbData, userKey.getBytes(), serverKey.getBytes());
        String recoveryData = null;
        try {
            recoveryData = new String(recovData, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return recoveryData;
    }

    public boolean setRecoveryData (String userKey, String recoveryData) {
        if (mAppID == null) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return false;
        }
        if (userKey == null) {
            System.out.println("[TrustSigner] : userKey is empty!");
            return false;
        }
        if (recoveryData == null) {
            System.out.println("[TrustSigner] : Recovery Data is empty!");
            return false;
        }
        mWbData = setWBRecoveryData (mAppID, userKey.getBytes(), recoveryData.getBytes());
        putStringSharedPreference(PREF_KEY_WB, byteArrayToHexString(mWbData));
        return true;
    }

    public byte[] hexStringToByteArray(String strings) {
        int len = strings.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(strings.charAt(i), 16) << 4)
                    + Character.digit(strings.charAt(i+1), 16));
        }
        return data;
    }

    public String byteArrayToHexString(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    public void test(){
        test1();
    }
}