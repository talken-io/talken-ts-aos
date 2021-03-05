package io.talken.trustsigner;

import android.content.Context;
import android.text.TextUtils;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

//import android.content.SharedPreferences;
//import android.preference.PreferenceManager;

public class TrustSigner {

    static {
        System.loadLibrary("trustsigner");
    }

    public static final String version = BuildConfig.VERSION_NAME;
    private static final String PREFERENCE_WB = "trustsigner.wbd";
    private static final String LOG_PREFIX = "[TrustSigner] : ";

    private Context mContext;
    private String mAppID;
    private String mWbPath;
    private byte[] mWbData;

    private native byte[]  getWBInitializeData               (String appID, String filePath);
    private native byte[]  getWBPublicKey                   (String appID, String filePath, byte[] wbData, String coinSymbol, int hdDepth, int hdChange, int hdIndex);
    private native byte[]  getWBSignatureData               (String appID, String filePath, byte[] wbData, String coinSymbol, int hdDepth, int hdChange, int hdIndex, byte[] hashMessage);
    private native byte[]  getWBRecoveryData                (String appID, String filePath, byte[] wbData, String userKey, String serverKey);
    private native boolean finishWBRecoveryData             (String appID, String filePath);
    private native byte[]  setWBRecoveryData                (String appID, String filePath, String userKey, String recoveryData);
    private native boolean getWBVerify                      (String appID, String filePath, byte[] wbData, String userKey, String recoveryData);
    private native void    generateMnemonic                 (String appID, String filePath);

    private void putStringSharedPreference (String key, String value) {
        SecureStorage.putSecurePreference(mContext, key, value);
    }

    private String getStringSharedPreference (String key) {
        return SecureStorage.getSecurePreference(mContext, key);
    }

    public TrustSigner (Context context, String appID) {
        mContext = context;
        mAppID = new String(appID);
        mWbPath = new String(mContext.getFilesDir() + "");

        File pFile = new File(mWbPath + "/" + PREFERENCE_WB);
        if(!pFile.exists()) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+ "WB table file is not found.");
            }
            new File(mWbPath).mkdirs();
        }

        if (BuildConfig.DEBUG) {
            System.out.println(LOG_PREFIX+"filePath = " + mWbPath + "/" + PREFERENCE_WB);
        }
    }

    public boolean initialize () {
        //저장된 WB데이터가 있는지 체크
        String strWbData = getStringSharedPreference(PREFERENCE_WB);
        if(TextUtils.isEmpty(strWbData)) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB Table Create!");
            }
            //WB데이터생성
            mWbData = getWBInitializeData(mAppID, mWbPath);
            if (mWbData == null) {
                if (BuildConfig.DEBUG) {
                    System.out.println(LOG_PREFIX+"Error! : WB Initialize failed.");
                }
                return false;
            }
            putStringSharedPreference(PREFERENCE_WB, byteArrayToHexString(mWbData));
            return true;
        } else {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB Table Load!");
            }
            mWbData = hexStringToByteArray(strWbData);
            return true;
        }
    }

    public void finalize() {
        if (mWbData != null) {
            Arrays.fill(mWbData, (byte) 0xFF);
            Arrays.fill(mWbData, (byte) 0x55);
            Arrays.fill(mWbData, (byte) 0x00);
        }
    }

    public boolean isEmptyData() {
        String strWbData = getStringSharedPreference(PREFERENCE_WB);
        return TextUtils.isEmpty(strWbData);
    }

    public String getVersion () {
        return version;
    }

    public String getPublicKey (String coinSym, int hdDepth, int hdChange, int hdIndex) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB data is empty!");
            }
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Coin symbol is empty!");
            }
            return null;
        } else if (hdDepth < 3 || hdDepth > 5) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD depth value invaild! (3 ~ 5)");
            }
            return null;
        } else if (coinSym.equals("XLM") && hdDepth != 3) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"XLM HD depth value invaild! (3)");
            }
            return null;
        } else if (hdChange < 0 || hdChange > 1) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD change value invaild! (0 ~ 1)");
            }
            return null;
        } else if (hdIndex < 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD index value invaild!");
            }
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
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB data is empty!");
            }
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Coin symbol is empty!");
            }
            return null;
        }

        // as-is
        int hdDepth = 3;
        // use filecoin
        if (coinSym.equals("FIL")) {
            hdDepth = 5;
        }

        byte[] pubKey = getWBPublicKey (mAppID, mWbPath, mWbData, coinSym, hdDepth, 0, 0);
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
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB data is empty!");
            }
            return null;
        } else if (TextUtils.isEmpty(coinSym) || coinSym.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Coin symbol is empty!");
            }
            return null;
        } else if (hdDepth < 3 || hdDepth > 5) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD depth value invaild! (3 ~ 5)");
            }
            return null;
        } else if (coinSym.equals("XLM") && hdDepth != 3) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"XLM HD depth value invaild! (3)");
            }
            return null;
        } else if (hdChange < 0 || hdChange > 1) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD change value invaild! (0 ~ 1)");
            }
            return null;
        } else if (hdIndex < 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"HD index value invaild!");
            }
            return null;
        } else if (TextUtils.isEmpty(hashMessage) || hashMessage.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Hash message is empty!");
            }
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
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return null;
        } else if (mWbData == null || mWbData.length <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB data is empty!");
            }
            return null;
        } else if (TextUtils.isEmpty(userKey) || userKey.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"User key is empty!");
            }
            return null;
        } else if (TextUtils.isEmpty(serverKey) || serverKey.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Server key is empty!");
            }
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

    public boolean finishRecoveryData () {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return false;
        }

        return finishWBRecoveryData (mAppID, mWbPath);
    }

    public boolean setRecoveryData (String userKey, String recoveryData) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return false;
        } else if (TextUtils.isEmpty(userKey) || userKey.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"userKey is empty!");
            }
            return false;
        } else if (TextUtils.isEmpty(recoveryData) || recoveryData.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Recovery Data is empty!");
            }
            return false;
        }

        mWbData = setWBRecoveryData (mAppID, mWbPath, userKey, recoveryData);
        if (mWbData == null) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Error! : WB Initialize failed.");
            }
            return false;
        }

        putStringSharedPreference(PREFERENCE_WB, byteArrayToHexString(mWbData));

        return true;
    }

    public boolean verifyRecoveryData(String userKey, String recoveryData) {
        if (TextUtils.isEmpty(mAppID) || mAppID.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"App ID is empty!");
            }
            return false;
        }
        if (mWbData == null || mWbData.length <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"WB data is empty!");
            }
            return false;
        }
        if (TextUtils.isEmpty(userKey) || userKey.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"User key is empty!");
            }
            return false;
        }
        if (TextUtils.isEmpty(recoveryData) || recoveryData.length() <= 0) {
            if (BuildConfig.DEBUG) {
                System.out.println(LOG_PREFIX+"Recovery Data is empty!");
            }
            return false;
        }

        boolean verifyResult = getWBVerify(mAppID, mWbPath, mWbData, userKey, recoveryData);

        return verifyResult;
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

    public void getMnemonic() {
        generateMnemonic(mAppID, mWbPath);
    }
}