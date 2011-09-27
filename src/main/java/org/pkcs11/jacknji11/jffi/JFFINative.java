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

package org.pkcs11.jacknji11.jffi;

import jnr.ffi.Address;
import jnr.ffi.Library;
import jnr.ffi.Pointer;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.NativeLongByReference;

/**
 * JFFI Native class.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFINative {
    static {
        Library.loadLibrary(JFFINative.class, "cryptoki");
    }

    public static native int C_Initialize(@In JFFI_CK_C_INITIALIZE_ARGS pInitArgs);
    public static native int C_Finalize(@In Address pReserved);
    public static native int C_GetInfo(@Out JFFI_CK_INFO pInfo);
    public static native int C_GetSlotList(@In boolean tokenPresent, @Out long[] pSlotList, @In @Out NativeLongByReference pulCount);
    public static native int C_GetSlotInfo(@In long slotID, @Out JFFI_CK_SLOT_INFO pInfo);
    public static native int C_GetTokenInfo(@In long slotID, @Out JFFI_CK_TOKEN_INFO pInfo);
    public static native int C_WaitForSlotEvent(@In long flags, @Out NativeLongByReference pSlot, @In Address pReserved);
    public static native int C_GetMechanismList(@In long slotID, @Out long[] pMechanismList, @In @Out NativeLongByReference pulCount);
    public static native int C_GetMechanismInfo(@In long slotID, @In long type, @Out JFFI_CK_MECHANISM_INFO pInfo);
    public static native int C_InitToken(@In long slotID, @In byte[] pPin, @In long ulPinLen, @In byte[] pLabel32);
    public static native int C_InitPIN(@In long hSession, @In byte[] pPin, @In long ulPinLen);
    public static native int C_SetPIN(@In long hSession, @In byte[] pOldPin, @In long ulOldLen, @In byte[] pNewPin, @In long ulNewLen);
    public static native int C_OpenSession(@In long slotID, @In long flags, @In Address application, @In Address notify, @In @Out NativeLongByReference phSession);
    public static native int C_CloseSession(@In long hSession);
    public static native int C_CloseAllSessions(@In long slotID);
    public static native int C_GetSessionInfo(@In long hSession, @Out JFFI_CK_SESSION_INFO pInfo);
    public static native int C_GetOperationState(@In long hSession, @In byte[] pOperationState, @In @Out NativeLongByReference pulOperationStateLen);
    public static native int C_SetOperationState(@In long hSession, @In byte[] pOperationState, @In long ulOperationStateLen, @In long hEncryptionKey, @In long hAuthenticationKey);
    public static native int C_Login(@In long hSession, @In long userType, @In byte[] pPin, @In long ulPinLen);
    public static native int C_Logout(@In long hSession);
    public static native int C_CreateObject(@In long hSession, @In Pointer pTemplate, @In long ulCount, @In @Out NativeLongByReference phObject);
    public static native int C_CopyObject(@In long hSession, long hObject, @In Pointer pTemplate, @In long ulCount, @In @Out NativeLongByReference phNewObject);
    public static native int C_DestroyObject(@In long hSession, @In long hObject);
    public static native int C_GetObjectSize(@In long hSession, @In long hObject, @In @Out NativeLongByReference pulSize);
    public static native int C_GetAttributeValue(@In long hSession, @In long hObject, @In @Out Pointer pTemplate, @In long ulCount);
    public static native int C_SetAttributeValue(@In long hSession, @In long hObject, @In Pointer pTemplate, @In long ulCount);
    public static native int C_FindObjectsInit(@In long hSession, @In Pointer pTemplate, @In long ulCount);
    public static native int C_FindObjects(@In long hSession, @Out long[] phObject, @In long ulMaxObjectCount, @In @Out NativeLongByReference pulObjectCount);
    public static native int C_FindObjectsFinal(@In long hSession);
    public static native int C_EncryptInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_Encrypt(@In long hSession, @In byte[] pData, @In long ulDataLen, @In byte[] pEncryptedData, @In @Out NativeLongByReference pulEncryptedDataLen);
    public static native int C_EncryptUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen, @Out byte[] pEncryptedPart, @In @Out NativeLongByReference pulEncryptedPartLen);
    public static native int C_EncryptFinal(@In long hSession, @Out byte[] pLastEncryptedPart, @In @Out NativeLongByReference pulLastEncryptedPartLen);
    public static native int C_DecryptInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_Decrypt(@In long hSession, @In byte[] pEncryptedData, @In long ulEncryptedDataLen, @In byte[] pData, @In @Out NativeLongByReference pulDataLen);
    public static native int C_DecryptUpdate(@In long hSession, @In byte[] pEncryptedPart, @In long ulEncryptedPartLen, @Out byte[] pData, @In @Out NativeLongByReference pulDataLen);
    public static native int C_DecryptFinal(@In long hSession, @Out byte[] pLastPart, @In @Out NativeLongByReference pulLastPartLen);
    public static native int C_DigestInit(@In long hSession, @In JFFI_CKM pMechanism);
    public static native int C_Digest(@In long hSession, @In byte[] pData, @In long ulDataLen, @Out byte[] pDigest, @In @Out NativeLongByReference pulDigestLen);
    public static native int C_DigestUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen);
    public static native int C_DigestKey(@In long hSession, @In long hKey);
    public static native int C_DigestFinal(@In long hSession, @Out byte[] pDigest, @In @Out NativeLongByReference pulDigestLen);
    public static native int C_SignInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_Sign(@In long hSession, @In byte[] pData, @In long ulDataLen, @Out byte[] pSignature, @In @Out NativeLongByReference pulSignatureLen);
    public static native int C_SignUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen);
    public static native int C_SignFinal(@In long hSession, @Out byte[] pSignature, @In @Out NativeLongByReference pulSignatureLen);
    public static native int C_SignRecoverInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_SignRecover(@In long hSession, @In byte[] pData, @In long ulDataLen, @Out byte[] pSignature, @In @Out NativeLongByReference pulSignatureLen);
    public static native int C_VerifyInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_Verify(@In long hSession, @In byte[] pData, @In long ulDataLen, @In byte[] pSignature, @In long ulSignatureLen);
    public static native int C_VerifyUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen);
    public static native int C_VerifyFinal(@In long hSession, @In byte[] pSignature, @In long ulSignatureLen);
    public static native int C_VerifyRecoverInit(@In long hSession, @In JFFI_CKM pMechanism, @In long hKey);
    public static native int C_VerifyRecover(@In long hSession, @In byte[] pSignature, @In long ulSignatureLen, @In byte[] pData, @In @Out NativeLongByReference pulDataLen);
    public static native int C_DigestEncryptUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen, @Out byte[] pEncryptedPart, @In @Out NativeLongByReference pulEncryptedPartLen);
    public static native int C_DecryptDigestUpdate(@In long hSession, @In byte[] pEncryptedPart, @In long ulEncryptedPartLen, @Out byte[] pPart, @In @Out NativeLongByReference pulPartLen);
    public static native int C_SignEncryptUpdate(@In long hSession, @In byte[] pPart, @In long ulPartLen, @Out byte[] pEncryptedPart, @In @Out NativeLongByReference pulEncryptedPartLen);
    public static native int C_DecryptVerifyUpdate(@In long hSession, @In byte[] pEncryptedPart, @In long ulEncryptedPartLen, @Out byte[] pPart, @In @Out NativeLongByReference pulPartLen);
    public static native int C_GenerateKey(@In long hSession, @In JFFI_CKM pMechanism, @In Pointer pTemplate, @In long ulCount, @Out NativeLongByReference phKey);
    public static native int C_GenerateKeyPair(@In long hSession, @In JFFI_CKM pMechanism, @In Pointer pPublicKeyTemplate, @In long ulPublicKeyAttributeCount, @In Pointer pPrivateKeyTemplate, @In long ulPrivateKeyAttributeCount, @Out NativeLongByReference phPublicKey, @Out NativeLongByReference phPrivateKey);
    public static native int C_WrapKey(@In long hSession, @In JFFI_CKM pMechanism, @In long hWrappingKey, @In long hKey, @Out byte[] pWrappedKey, @In @Out NativeLongByReference pulWrappedKeyLen);
    public static native int C_UnwrapKey(@In long hSession, @In JFFI_CKM pMechanism, @In long hUnwrappingKey, @In byte[] pWrappedKey, @In long ulWrappedKeyLen, @In Pointer pTemplate, @In long ulAttributeCount, @Out NativeLongByReference phKey);
    public static native int C_DeriveKey(@In long hSession, @In JFFI_CKM pMechanism, @In long hBaseKey, @In Pointer pTemplate, @In long ulAttributeCount, @Out NativeLongByReference phKey);
    public static native int C_SeedRandom(@In long hSession, @In byte[] pSeed, @In long ulSeedLen);
    public static native int C_GenerateRandom(@In long hSession, @In byte[] pRandomData, @In long ulRandomLen);
    public static native int C_GetFunctionStatus(@In long hSession);
    public static native int C_CancelFunction(@In long hSession);
}
