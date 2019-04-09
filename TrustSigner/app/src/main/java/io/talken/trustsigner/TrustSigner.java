package io.talken.trustsigner;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.text.TextUtils;

import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class TrustSigner {

    static {
        System.loadLibrary("trustsigner");
    }

    public static final String version = "0.9.6";
    private static final String PREFERENCE_WB = "trustsigner.wbd";

    private Context mContext;
    private String mAppID;
    private String mWbPath;
    private byte[] mWbData;

    private native byte[] getWBInitializeData (String appID, String filePath);
    private native byte[] getWBPublicKey      (String appID, String filePath, byte[] wbData, String coinSymbol, int hdDepth, int hdChange, int hdIndex);
    private native byte[] getWBSignatureData  (String appID, String filePath, byte[] wbData, String coinSymbol, int hdDepth, int hdChange, int hdIndex, byte[] hashMessage);
    private native byte[] getWBRecoveryData   (String appID, String filePath, byte[] wbData, String userKey, String serverKey);
    private native byte[] setWBRecoveryData   (String appID, String filePath, String userKey, String recoveryData);

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

//    private boolean putWBDataFile (Context context) {
//        if (mWbData == null) {
//            System.out.println("[TrustSigner] : WB Data is null.");
//            return false;
//        }
//
//        FileOutputStream fos = null;
//        try {
//            File pFile = new File(mWbPath + PREFERENCE_WB);
//            fos = new FileOutputStream(pFile);
//            fos.write(mWbData, 0, mWbData.length);
//        } catch (IOException e) {
//            System.out.println(e);
//        } finally {
//            try {
//                fos.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//        return true;
//    }

//    private boolean getWBDataFile (Context context) {
//        File pFile = new File(mWbPath + "/" + PREFERENCE_WB);
//        if(!pFile.exists()) {
//            System.out.println("[TrustSigner] : WB Data file is not found.");
//            new File(mWbPath).mkdirs();
//            return false;
//        }
//
//        int readcount = 0;
//        FileInputStream fis = null;
//        try {
//            fis = new FileInputStream(pFile);
//            readcount = (int) pFile.length();
//            mWbData = new byte[readcount];
//            fis.read(mWbData);
//        } catch (IOException e) {
//            System.out.println(e);
//        } finally {
//            try {
//                fis.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//        return true;
//    }

    public TrustSigner (Context context, String appID) {
        mContext = context;
        mAppID = new String(appID);
        mWbPath = new String(mContext.getFilesDir() + "");

        File pFile = new File(mWbPath + "/" + PREFERENCE_WB);
        if(!pFile.exists()) {
            System.out.println("[TrustSigner] : WB table file is not found.");
            new File(mWbPath).mkdirs();
        }

        System.out.println("[TrustSigner] : appSign = " + getSignJava(mContext));
        System.out.println("[TrustSigner] : filePath = " + mWbPath + "/" + PREFERENCE_WB);
    }

    public void initialize () {
        //저장된 WB데이터가 있는지 체크
        System.out.println("### MYSEO : TIME CHECK #1 - START");
        String strWbData = getStringSharedPreference(PREFERENCE_WB, "");

        System.out.println("### MYSEO : TIME CHECK #2");
        if(TextUtils.isEmpty(strWbData)) {
            //WB데이터생성
            mWbData = getWBInitializeData(mAppID, mWbPath);
            if (mWbData == null) {
                System.out.println("Error! : WB Initialize failed.");
                throw new NullPointerException();
            }

            System.out.println("### MYSEO : TIME CHECK #3");
            putStringSharedPreference(PREFERENCE_WB, byteArrayToHexString(mWbData));

            System.out.println("### MYSEO : TIME CHECK #4 - END");
        } else {
            mWbData = hexStringToByteArray(strWbData);
        }
    }

//    public void initialize () {
//        System.out.println("### MYSEO : TIME CHECK #1");
//        if (mWbData == null || mWbData.length <= 0) {
//            if (getWBDataFile(mContext) == false) {
//                System.out.println("### MYSEO : TIME CHECK #2");
//                mWbData = getWBInitializeData(mAppID, mWbPath);
//                if (mWbData == null || mWbData.length <= 0) {
//                    System.out.println("[TrustSigner] : Error! WB initialize failed.");
//                    return;
//                }
//                System.out.println("### MYSEO : TIME CHECK #3");
//                if (putWBDataFile(mContext) == false) {
//                    System.out.println("[TrustSigner] : Error! WB initialize write failed.");
//                    return;
//                }
//            }
//        }
//        System.out.println("### MYSEO : TIME CHECK #4");
//    }

    public void finalize() {
        Arrays.fill(mWbData, (byte) 0xFF);
        Arrays.fill(mWbData, (byte) 0x55);
        Arrays.fill(mWbData, (byte) 0x00);
    }

    public String getVersion () {
        return version;
    }

    public String getPublicKey (String coinSym, int hdDepth, int hdChange, int hdIndex) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        } else if (hdDepth < 3 || hdDepth > 5) {
            System.out.println("[TrustSigner] : HD depth value invaild! (3 ~ 5)");
            return null;
        } else if (coinSym.equals("XLM") && hdDepth != 3) {
            System.out.println("[TrustSigner] : XLM HD depth value invaild! (3)");
            return null;
        } else if (hdChange < 0 || hdChange > 1) {
            System.out.println("[TrustSigner] : HD change value invaild! (0 ~ 1)");
            return null;
        } else if (hdIndex < 0) {
            System.out.println("[TrustSigner] : HD index value invaild!");
            return null;
        }

        byte[] pubKey = getWBPublicKey (mAppID, mWbPath, mWbData, coinSym, hdDepth, hdChange, hdIndex);
        if (pubKey == null) {
            return null;
        }

        String publicKey = null;
        try {
            publicKey = new String(pubKey, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public String getAccountPublicKey (String coinSym) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        }

        byte[] pubKey = getWBPublicKey (mAppID, mWbPath, mWbData, coinSym, 3, 0, 0);
        if (pubKey == null) {
            return null;
        }

        String publicKey = null;
        try {
            publicKey = new String(pubKey, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public String getSignatureData (String coinSym, int hdDepth, int hdChange, int hdIndex, String hashMessage) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            System.out.println("[TrustSigner] : Coin symbol is empty!");
            return null;
        } else if (hdDepth < 3 || hdDepth > 5) {
            System.out.println("[TrustSigner] : HD depth value invaild! (3 ~ 5)");
            return null;
        } else if (coinSym.equals("XLM") && hdDepth != 3) {
            System.out.println("[TrustSigner] : XLM HD depth value invaild! (3)");
            return null;
        } else if (hdChange < 0 || hdChange > 1) {
            System.out.println("[TrustSigner] : HD change value invaild! (0 ~ 1)");
            return null;
        } else if (hdIndex < 0) {
            System.out.println("[TrustSigner] : HD index value invaild!");
            return null;
        } else if (TextUtils.isEmpty(hashMessage) || hashMessage.length() <= 0) {
            System.out.println("[TrustSigner] : Hash message is empty!");
            return null;
        }

        byte[] signature = getWBSignatureData (mAppID, mWbPath, mWbData, coinSym, hdDepth, hdChange, hdIndex, hexStringToByteArray(hashMessage));
        if (signature == null) {
            return null;
        }

        return byteArrayToHexString(signature);
    }

    public String getRecoveryData (String userKey, String serverKey) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            System.out.println("[TrustSigner] : WB data is empty!");
            return null;
        } else if (TextUtils.isEmpty(userKey) || userKey.length() <= 0) {
            System.out.println("[TrustSigner] : User key is empty!");
            return null;
        } else if (TextUtils.isEmpty(serverKey) || serverKey.length() <= 0) {
            System.out.println("[TrustSigner] : Server key is empty!");
            return null;
        }

        byte[] recovData = getWBRecoveryData (mAppID, mWbPath, mWbData, userKey, serverKey);
        if (recovData == null) {
            return null;
        }

        String recoveryData = null;
        try {
            recoveryData = new String(recovData, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return recoveryData;
    }

    public boolean setRecoveryData (String userKey, String recoveryData) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            System.out.println("[TrustSigner] : App ID is empty!");
            return false;
        } else if (TextUtils.isEmpty(userKey) || userKey.length() <= 0) {
            System.out.println("[TrustSigner] : userKey is empty!");
            return false;
        } else if (TextUtils.isEmpty(recoveryData) || recoveryData.length() <= 0) {
            System.out.println("[TrustSigner] : Recovery Data is empty!");
            return false;
        }

        mWbData = setWBRecoveryData (mAppID, mWbPath, userKey, recoveryData);
        if (mWbData == null) {
            System.out.println("Error! : WB Initialize failed.");
            throw new NullPointerException();
        }

        putStringSharedPreference(PREFERENCE_WB, byteArrayToHexString(mWbData));

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
}