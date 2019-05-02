package io.talken.trustsigner;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SecureStorage {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "io.talken.trustsigner";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM = "RSA";
    private static final int KEY_VALID_YEAR = 1000;

    private static final String SECURE_PREFERENCES = "secure_preferences";

    private static String encrypt(Context context, String plainText) throws IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
            CertificateException, UnrecoverableEntryException, IOException, KeyStoreException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyStore.Entry entry = createKeys(context);

        if (entry instanceof KeyStore.PrivateKeyEntry) {
            Certificate certificate = ((KeyStore.PrivateKeyEntry) entry).getCertificate();
            PublicKey publicKey = certificate.getPublicKey();
            byte[] bytes = plainText.getBytes(UTF_8);
            byte[] encryptedBytes = encryptUsingKey(publicKey, bytes);
            byte[] base64encryptedBytes = Base64.encode(encryptedBytes, Base64.DEFAULT);
            return new String(base64encryptedBytes);
        }
        return null;
    }

    private static String decrypt(String cipherText) throws IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException,
            IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.PrivateKeyEntry) {
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            byte[] bytes = cipherText.getBytes(UTF_8);
            byte[] base64encryptedBytes = Base64.decode(bytes, Base64.DEFAULT);
            byte[] decryptedBytes = decryptUsingKey(privateKey, base64encryptedBytes);
            return new String(decryptedBytes);
        }
        return null;
    }

    private static byte[] encryptUsingKey(PublicKey publicKey, byte[] bytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher inCipher = Cipher.getInstance(CIPHER);
        inCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return inCipher.doFinal(bytes);
    }

    private static byte[] decryptUsingKey(PrivateKey privateKey, byte[] bytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher inCipher = Cipher.getInstance(CIPHER);
        inCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return inCipher.doFinal(bytes);
    }

    private static KeyStore.Entry createKeys(Context context) throws CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        boolean containsAlias = keyStore.containsAlias(KEY_ALIAS);

        if (!containsAlias) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, ANDROID_KEY_STORE);
            Calendar start = Calendar.getInstance(Locale.getDefault());
            Calendar end = Calendar.getInstance(Locale.getDefault());
            end.add(Calendar.YEAR, KEY_VALID_YEAR);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(KEY_ALIAS)
                    .setSubject(new X500Principal("CN="+KEY_ALIAS))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }
        return keyStore.getEntry(KEY_ALIAS, null);
    }

    public static void putSecurePreference(Context context, String key, String value) {
        String encryptValue = null;
        try {
            encryptValue = encrypt(context, value);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        SharedPreferences sp = context.getSharedPreferences(SECURE_PREFERENCES, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.putString(key, encryptValue);
        editor.apply();
    }

    public static String getSecurePreference(Context context, String key) {
        String result = null;
        SharedPreferences sp = context.getSharedPreferences(SECURE_PREFERENCES, Context.MODE_PRIVATE);
        result = sp.getString(key, null);

        try {
            result = decrypt(result);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static void clearSecureStorage(Context context) {
        SharedPreferences sp = context.getSharedPreferences(SECURE_PREFERENCES, Context.MODE_PRIVATE);
        sp.edit().clear().apply();
    }
}
