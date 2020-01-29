package br.com.ygsoftware.fingerprint;

import android.os.Build;
import android.print.PrinterId;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

public class FingerprintException extends RuntimeException {

    public static final int
            HARDWARE_NOT_FOUND = 0,
            SKD_VERSION_UNSUPPORTED = 1,
            PERMISSION_MISSION = 2,
            KEY_GUARDIAN_DISABLED = 3,
            EMPTY_FINGERPRINT = 4;

    @IntDef({HARDWARE_NOT_FOUND, SKD_VERSION_UNSUPPORTED, PERMISSION_MISSION, KEY_GUARDIAN_DISABLED, EMPTY_FINGERPRINT})
    private @interface ExceptionType {}

    @ExceptionType
    private int type;

    private FingerprintException(String message, @ExceptionType int type) {
        super(message);
        this.type = type;
    }

    @ExceptionType
    public int getType() {
        return type;
    }

    public static FingerprintException getHardwareNotFound() {
        return new FingerprintException("Fingerprint sensor not available", HARDWARE_NOT_FOUND);
    }

    public static FingerprintException getSdkVersionUnsupported() {
        return new FingerprintException("Android Version is less of M (23)", SKD_VERSION_UNSUPPORTED);
    }

    public static FingerprintException getPermissionMissing() {
        return new FingerprintException("Fingerprint or Biometric permission not allowed", PERMISSION_MISSION);
    }

    public static FingerprintException getKeyGuardianDisabled() {
        return new FingerprintException("Key Guardian not enabled", KEY_GUARDIAN_DISABLED);
    }

    public static FingerprintException getEmptyFingerprint() {
        return new FingerprintException("Not has fingerprint configured", EMPTY_FINGERPRINT);
    }

}
