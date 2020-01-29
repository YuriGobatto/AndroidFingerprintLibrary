package br.com.ygsoftware.fingerprint;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class Fingerprint {

    private FragmentActivity context;
    private String title;
    private String userIdentity;
    private String description;
    private FingerprintKey key;
    private OnExecuteListener listener;

    private FingerprintExecutor executor;

    private Fingerprint(FragmentActivity context) {
        this.context = context;
    }

    FragmentActivity getContext() {
        return context;
    }

    public String getTitle() {
        return title;
    }

    public String getUserIdentity() {
        return userIdentity;
    }

    public String getDescription() {
        return description;
    }

    public FingerprintKey getKey() {
        return key;
    }

    OnExecuteListener getListener() {
        return listener;
    }

    public void show() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
            return;
        if (executor == null)
            executor = new FingerprintExecutor(context, this);
        if (!executor.isShowing())
            executor.show();
    }

    public void hide() {
        if (executor.isShowing())
            executor.hide();
    }

    public static class Builder {

        private Fingerprint fingerprint;

        public Builder(@NonNull FragmentActivity context) {
            if (context == null) {
                throw new NullPointerException("context doesn't is null");
            }
            fingerprint = new Fingerprint(context);
        }

        @NonNull
        public Builder setTitle(@NonNull String title) {
            fingerprint.title = title;
            return this;
        }

        @NonNull
        public Builder setUserIdentity(@NonNull String userIdentity) {
            if (TextUtils.isEmpty(userIdentity)) {
                throw new NullPointerException("User Identity doesn't is null or empty");
            }
            fingerprint.userIdentity = userIdentity;
            return this;
        }

        @NonNull
        public Builder setDescription(@NonNull String description) {
            if (TextUtils.isEmpty(description)) {
                throw new NullPointerException("Description doesn't is null or empty");
            }
            fingerprint.description = description;
            return this;
        }

        @NonNull
        public Builder setKey(@NonNull FingerprintKey key) {
            fingerprint.key = key;
            return this;
        }

        @NonNull
        public Builder setOnExecuteListener(@NonNull OnExecuteListener listener) {
            fingerprint.listener = listener;
            return this;
        }

        public Fingerprint build() {

            try {
                validate();
            } catch (FingerprintException e) {
                fingerprint.listener.onDeviceError(e);
            }

            if (TextUtils.isEmpty(fingerprint.title)) {
                throw new NullPointerException("Title doesn't is null or empty");
            }

            if (fingerprint.key == null) {
                throw new NullPointerException("Key doesn't is null");
            }

            if (fingerprint.listener == null) {
                throw new NullPointerException("onExecuteListener doesn't is null");
            }

            return fingerprint;
        }

        @SuppressLint("NewApi")
        private void validate() {

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                throw FingerprintException.getSdkVersionUnsupported();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (ContextCompat.checkSelfPermission(fingerprint.context,
                        Manifest.permission.USE_BIOMETRIC) != PackageManager.PERMISSION_GRANTED) {
                    throw FingerprintException.getPermissionMissing();
                }
            } else if (ContextCompat.checkSelfPermission(fingerprint.context,
                    Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                throw FingerprintException.getPermissionMissing();
            }

            if (FingerprintUtils.hasSensorAvailable(fingerprint.context)) {
                throw FingerprintException.getHardwareNotFound();
            }

            if (FingerprintUtils.hasLockScreen(fingerprint.context)) {
                throw FingerprintException.getKeyGuardianDisabled();
            }

            if (FingerprintUtils.hasFingerprintRegistered(fingerprint.context)) {
                throw FingerprintException.getEmptyFingerprint();
            }

        }

    }


    static class FingerprintKey {

        private String name;
        private FingerprintKeyType type;

        public FingerprintKey(String name, FingerprintKeyType type) {
            if (TextUtils.isEmpty(name)) {
                throw new NullPointerException("name doesn't is null or empty");
            }

            if (type == null) {
                throw new NullPointerException("type doesn't is null");
            }
            this.name = name;
            this.type = type;
        }

        public String getName() {
            return name;
        }

        public FingerprintKeyType getType() {
            return type;
        }
    }

    public enum FingerprintKeyType {
        RSA,
        AES;
    }

    public static class RSAKey extends FingerprintKey {

        private boolean encrypt;

        public RSAKey(String name, boolean encrypt) {
            super(name, FingerprintKeyType.RSA);
            this.encrypt = encrypt;
        }

        public boolean isEncrypt() {
            return encrypt;
        }
    }

    public static class AESKey extends FingerprintKey {

        private boolean encrypt;
        private String iv;

        public AESKey(String name) {
            super(name, FingerprintKeyType.AES);
            this.encrypt = true;
        }

        public AESKey(String name, String iv) {
            super(name, FingerprintKeyType.AES);
            this.iv = iv;
            this.encrypt = false;
        }

        public boolean isEncrypt() {
            return encrypt;
        }

        public String getIv() {
            return iv;
        }
    }

    public interface OnExecuteListener {

        void onCancel();

        void onApiError(int errorCode, CharSequence errString);

        void onDeviceError(Exception e);

        void onSuccess(Cipher cipher, Mac mac, Signature signature);

    }

}
