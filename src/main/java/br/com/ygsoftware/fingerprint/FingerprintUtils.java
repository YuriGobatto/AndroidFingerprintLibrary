package br.com.ygsoftware.fingerprint;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.RequiresApi;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class FingerprintUtils {

    static boolean hasSensorAvailable(Context context) {
        return FingerprintManagerCompat.from(context).isHardwareDetected();
    }

    static boolean hasFingerprintRegistered(Context context) {
        return FingerprintManagerCompat.from(context).hasEnrolledFingerprints();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static boolean hasLockScreen(Context context) {
        return context.getSystemService(KeyguardManager.class)
                .isDeviceLocked();
    }

    private static KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return keyStore;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static void generateKeyAES(String alias) {
        try {

            KeyStore keyStore = getKeyStore();
            if (keyStore.containsAlias(alias)) {
                return;
            }
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            keyGenerator.generateKey();

        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | IOException exc) {
            exc.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static Cipher initCipherAES(String alias) {
        return initCipherAES(new Fingerprint.AESKey(alias));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static Cipher initCipherAES(Fingerprint.AESKey key) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);

        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            KeyStore keyStore = getKeyStore();
            SecretKey secretKey = (SecretKey) keyStore.getKey(key.getName(),
                    null);
            if (key.isEncrypt())
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            else {
                byte[] iv = getIV(key.getIv());
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            return cipher;


        } catch (KeyPermanentlyInvalidatedException e) {
            return null;

        } catch (KeyStoreException | CertificateException |
                UnrecoverableKeyException | IOException |
                NoSuchAlgorithmException | InvalidKeyException |
                InvalidAlgorithmParameterException e) {

            throw new RuntimeException("Failed to init Cipher", e);
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    static void generateKeyRSA(String alias) {
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyGenerator.initialize(
                    new KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_ENCRYPT |
                                    KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setUserAuthenticationRequired(true)
                            .build());
            keyGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static Cipher initCipherRSA(Fingerprint.RSAKey key) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }
        try {
            KeyStore keyStore = getKeyStore();
            if (key.isEncrypt()) {
                PublicKey publicKey = keyStore.getCertificate(key.getName()).getPublicKey();
                PublicKey unrestrictedPublicKey = KeyFactory.getInstance(publicKey.getAlgorithm()).generatePublic(
                        new X509EncodedKeySpec(publicKey.getEncoded()));
                OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                cipher.init(Cipher.ENCRYPT_MODE, unrestrictedPublicKey, spec);
            } else {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(key.getName(), null);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            }

            return cipher;

        } catch (InvalidKeySpecException e) {
            return null;
        } catch (KeyStoreException | InvalidAlgorithmParameterException |
                InvalidKeyException | CertificateException |
                NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    public static String encryptRSA(String alias, String text) {
        try {
            byte[] bytes = initCipherRSA(new Fingerprint.RSAKey(alias, true)).doFinal(text.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(bytes, Base64.NO_WRAP);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptRSA(Cipher cipher, String text) {
        try {
            byte[] bytes = Base64.decode(text, Base64.NO_WRAP);
            return new String(cipher.doFinal(bytes));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encryptAES(Cipher cipher, String text) {
        try {
            String data = Base64.encodeToString(cipher.doFinal(text.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
            String iv = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP);
            String input = data + "@" + iv;
            return Base64.encodeToString(input.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptAES(Cipher cipher, String text) {
        try {
            String input = new String(Base64.decode(text, Base64.NO_WRAP));
            String[] parts = input.split("@");
            byte[] data = cipher.doFinal(Base64.decode(parts[0], Base64.NO_WRAP));
            return new String(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static byte[] getIV(String text) {
        String input = new String(Base64.decode(text, Base64.NO_WRAP));
        String[] parts = input.split("@");
        return Base64.decode(parts[parts.length - 1], Base64.NO_WRAP);
    }
}
