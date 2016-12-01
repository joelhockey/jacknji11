/*
 * Copyright 2010-2011 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.pkcs11.jacknji11;

import java.util.Map;

/**
 * PKCS#11 CK_TOKEN_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_TOKEN_INFO {
    public static final long CKF_RNG                   = 0x00000001;
    public static final long CKF_WRITE_PROTECTED       = 0x00000002;
    public static final long CKF_LOGIN_REQUIRED        = 0x00000004;
    public static final long CKF_USER_PIN_INITIALIZED  = 0x00000008;
    public static final long CKF_RESTORE_KEY_NOT_NEEDED=  0x00000020;
    public static final long CKF_CLOCK_ON_TOKEN        =  0x00000040;
    public static final long CKF_PROTECTED_AUTHENTICATION_PATH =0x00000100;
    public static final long CKF_DUAL_CRYPTO_OPERATIONS  =0x00000200;
    public static final long CKF_TOKEN_INITIALIZED       =0x00000400;
    public static final long CKF_SECONDARY_AUTHENTICATION = 0x00000800;
    public static final long CKF_USER_PIN_COUNT_LOW       =0x00010000;
    public static final long CKF_USER_PIN_FINAL_TRY       =0x00020000;
    public static final long CKF_USER_PIN_LOCKED          =0x00040000;
    public static final long CKF_USER_PIN_TO_BE_CHANGED   =0x00080000;
    public static final long CKF_SO_PIN_COUNT_LOW         =0x00100000;
    public static final long CKF_SO_PIN_FINAL_TRY         =0x00200000;
    public static final long CKF_SO_PIN_LOCKED            =0x00400000;
    public static final long CKF_SO_PIN_TO_BE_CHANGED     =0x00800000;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_TOKEN_INFO.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String L2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }

    public byte[] label = new byte[32];
    public byte[] manufacturerID = new byte[32];
    public byte[] model = new byte[16];
    public byte[] serialNumber = new byte[16];
    public long flags;
    public long ulMaxSessionCount;
    public long ulSessionCount;
    public long ulMaxRwSessionCount;
    public long ulRwSessionCount;
    public long ulMaxPinLen;
    public long ulMinPinLen;
    public long ulTotalPublicMemory;
    public long ulFreePublicMemory;
    public long ulTotalPrivateMemory;
    public long ulFreePrivateMemory;
    public CK_VERSION hardwareVersion = new CK_VERSION();
    public CK_VERSION firmwareVersion = new CK_VERSION();
    public byte[] utcTime = new byte[16];


    /** @return True, if the token has a random number generator. False, otherwise. */
    public boolean isRNG() {
        return (flags & CKF_RNG) != 0L;
    }

    /** @return True, if the token is write protected. False, otherwise. */
    public boolean isWriteProtected() {
        return (flags & CKF_WRITE_PROTECTED) != 0L;
    }

    /** @return True, if the token requires the user to log in before certain operations can be performed. False, otherwise. */
    public boolean isLoginRequired() {
        return (flags & CKF_LOGIN_REQUIRED) != 0L;
    }

    /** @return True, if the user-PIN is already initialized. False, otherwise. */
    public boolean isUserPinInitialized() {
        return (flags & CKF_USER_PIN_INITIALIZED) != 0L;
    }

    /** @return True, if a successful save of a sessions cryptographic operations state always contains all keys needed to restore the state of the session. False, otherwise. */
    public boolean isRestoreKeyNotNeeded() {
        return (flags & CKF_RESTORE_KEY_NOT_NEEDED) != 0L;
    }

    /** @return True, if the token has its own clock. False, otherwise. */
    public boolean isClockOnToken() {
        return (flags & CKF_CLOCK_ON_TOKEN) != 0L;
    }

    /** @return True, if the token has an protected authentication path. This means that a user may log in without providing a PIN to the login method, because the token has other means to authenticate the user; e.g. a PIN-pad on the reader or some biometric authentication.. False, otherwise. */
    public boolean isProtectedAuthenticationPath() {
        return (flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0L;
    }

    /** @return True, if the token supports dual crypto operations. False, otherwise. */
    public boolean isDualCryptoOperations() {
        return (flags & CKF_DUAL_CRYPTO_OPERATIONS) != 0L;
    }

    /** @return True, if the token is already initialized. False, otherwise. */
    public boolean isTokenInitialized() {
        return (flags & CKF_TOKEN_INITIALIZED) != 0L;
    }

    /** @return True, if the token supports secondary authentication. False, otherwise. */
    public boolean isSecondaryAuthentication() {
        return (flags & CKF_SECONDARY_AUTHENTICATION) != 0L;
    }

    /** @return True, if the the user-PIN has been entered incorrectly at least one since the last successful authentication. False, otherwise. */
    public boolean isUserPinCountLow() {
        return (flags & CKF_USER_PIN_COUNT_LOW) != 0L;
    }

    /** @return True, if the user has just one try left to supply the correct PIN before the user-PIN gets locked. False, otherwise. */
    public boolean isUserPinFinalTry() {
        return (flags & CKF_USER_PIN_FINAL_TRY) != 0L;
    }

    /** @return True, if the user-PIN is locked. False, otherwise. */
    public boolean isUserPinLocked() {
        return (flags & CKF_USER_PIN_LOCKED) != 0L;
    }

    /** @return True, if the user PIN value is the default value set by token initialization or manufacturing. False, otherwise. */
    public boolean isUserPinToBeChanged() {
        return (flags & CKF_USER_PIN_TO_BE_CHANGED) != 0L;
    }

    /** @return True, if the the security officer-PIN has been entered incorrectly at least one since the last successful authentication. False, otherwise. */
    public boolean isSoPinCountLow() {
        return (flags & CKF_SO_PIN_COUNT_LOW) != 0L;
    }

    /** @return True, if the security officer has just one try left to supply the correct PIN before the security officer-PIN gets locked. False, otherwise. */
    public boolean isSoPinFinalTry() {
        return (flags & CKF_SO_PIN_FINAL_TRY) != 0L;
    }

    /** @return True, if the security officer-PIN is locked. False, otherwise. */
    public boolean isSoPinLocked() {
        return (flags & CKF_SO_PIN_LOCKED) != 0L;
    }

    /** @return True, if the security officer PIN value is the default value set by token initialization or manufacturing. False, otherwise. */
    public boolean isSoPinToBeChanged() {
        return (flags & CKF_SO_PIN_TO_BE_CHANGED) != 0L;
    }
    
    /** @return string */
    public String toString() {
        return String.format("(\n  label=%s\n  manufacturerID=%s\n  model=%s\n  serialNumber=%s\n  flags=0x%08x{%s}" +
                "\n  maxSessionCount=%d\n  sessionCount=%d\n  maxRwSessionCount=%d\n  rwSessionCount=%d" +
                "\n  maxPinLen=%d\n  minPinLen=%d\n  totalPublicMemory=%d\n  freePublicMemory=%d" +
                "\n  totalPrivateMemory=%d\n  freePrivateMemory=%d" +
                "\n  hardwareVersion=%d.%d\n  firmwareVersion=%d.%d\n  utcTime=%s\n)",
                Buf.escstr(label), Buf.escstr(manufacturerID), Buf.escstr(model), Buf.escstr(serialNumber),
                flags, f2s(flags), ulMaxSessionCount, ulSessionCount,
                ulMaxRwSessionCount, ulRwSessionCount,
                ulMaxPinLen, ulMinPinLen,
                ulTotalPublicMemory, ulFreePublicMemory,
                ulTotalPrivateMemory, ulFreePrivateMemory,
                hardwareVersion.major & 0xff, hardwareVersion.minor & 0xff,
                firmwareVersion.major & 0xff, firmwareVersion.minor & 0xff,
                Buf.escstr(utcTime));
    }
}
