package br.com.ygsoftware.fingerprint;

import android.os.Build;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AlertDialog;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

class FingerprintExecutor extends BiometricPrompt.AuthenticationCallback {

    private BiometricPrompt prompt;
    private Executor executor;
    private Fingerprint fingerprint;
    private boolean showing;

    public FingerprintExecutor(FragmentActivity context, Fingerprint fingerprint) {
        this.fingerprint = fingerprint;
        this.executor = Executors.newSingleThreadExecutor();
        prompt = new BiometricPrompt(context, executor, this);
    }

    @Override
    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
            fingerprint.getListener().onCancel();
        }
        fingerprint.getListener().onApiError(errorCode, errString);
    }

    @Override
    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
        BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
        if (cryptoObject != null)
            fingerprint.getListener().onSuccess(cryptoObject.getCipher(), cryptoObject.getMac(), cryptoObject.getSignature());
        else
            fingerprint.getListener().onDeviceError(new NullPointerException("Crypto Object is null"));
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void show() {
        BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(fingerprint.getTitle());
        if (!TextUtils.isEmpty(fingerprint.getUserIdentity()))
            builder.setDescription(fingerprint.getUserIdentity());

        if (!TextUtils.isEmpty(fingerprint.getDescription()))
            builder.setDescription(fingerprint.getDescription());

        builder.setNegativeButtonText(fingerprint.getContext().getString(android.R.string.cancel));
        BiometricPrompt.CryptoObject cryptoObject = getCrypto();
        if (cryptoObject == null)
            return;

        prompt.authenticate(builder.build(), cryptoObject);
        showing = true;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private BiometricPrompt.CryptoObject getCrypto() {
        if (fingerprint.getKey() == null) {
            return null;
        }
        Fingerprint.FingerprintKey key = fingerprint.getKey();
        Cipher cipher = null;
        if (key.getType() == Fingerprint.FingerprintKeyType.AES) {
            FingerprintUtils.generateKeyAES(key.getName());
            cipher = FingerprintUtils.initCipherAES((Fingerprint.AESKey) key);
        } else {
            FingerprintUtils.generateKeyRSA(key.getName());
            cipher = FingerprintUtils.initCipherRSA((Fingerprint.RSAKey) key);
            if (((Fingerprint.RSAKey) key).isEncrypt()) {
                fingerprint.getListener().onSuccess(cipher, null, null);
                return null;
            }
        }
        if (cipher == null) {
            return null;
        }
        return new BiometricPrompt.CryptoObject(cipher);
    }

    public void hide() {
        prompt.cancelAuthentication();
        showing = false;
    }

    public boolean isShowing() {
        return showing;
    }
}
