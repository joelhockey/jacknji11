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

package org.pkcs11.jacknji11.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * JNA Native class with direct mapped methods.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNANative {
    static {
        com.sun.jna.Native.register("cryptoki");
    }

    public static native int C_Initialize(JNA_CK_C_INITIALIZE_ARGS pInitArgs);
    public static native int C_Finalize(Pointer pReserved);
    public static native int C_GetInfo(JNA_CK_INFO pInfo);
    public static native int C_GetSlotList(byte tokenPresent, LongArray pSlotList, NativeLongByReference pulCount);
    public static native int C_GetSlotInfo(NativeLong slotID, JNA_CK_SLOT_INFO pInfo);
    public static native int C_GetTokenInfo(NativeLong slotID, JNA_CK_TOKEN_INFO pInfo);
    public static native int C_WaitForSlotEvent(NativeLong flags, NativeLongByReference pSlot, Pointer pReserved);
    public static native int C_GetMechanismList(NativeLong slotID, LongArray pMechanismList, NativeLongByReference pulCount);
    public static native int C_GetMechanismInfo(NativeLong slotID, NativeLong type, JNA_CK_MECHANISM_INFO pInfo);
    public static native int C_InitToken(NativeLong slotID, byte[] pPin, NativeLong ulPinLen, byte[] pLabel32);
    public static native int C_InitPIN(NativeLong hSession, byte[] pPin, NativeLong ulPinLen);
    public static native int C_SetPIN(NativeLong hSession, byte[] pOldPin, NativeLong ulOldLen, byte[] pNewPin, NativeLong ulNewLen);
    public static native int C_OpenSession(NativeLong slotID, NativeLong flags, Pointer application, JNA_CK_NOTIFY notify, NativeLongByReference phSession);
    public static native int C_CloseSession(NativeLong hSession);
    public static native int C_CloseAllSessions(NativeLong slotID);
    public static native int C_GetSessionInfo(NativeLong hSession, JNA_CK_SESSION_INFO pInfo);
    public static native int C_GetOperationState(NativeLong hSession, byte[] pOperationState, NativeLongByReference pulOperationStateLen);
    public static native int C_SetOperationState(NativeLong hSession, byte[] pOperationState, NativeLong ulOperationStateLen, NativeLong hEncryptionKey, NativeLong hAuthenticationKey);
    public static native int C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);
    public static native int C_Logout(NativeLong hSession);
    public static native int C_CreateObject(NativeLong hSession, Template pTemplate, NativeLong ulCount, NativeLongByReference phObject);
    public static native int C_CopyObject(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount, NativeLongByReference phNewObject);
    public static native int C_DestroyObject(NativeLong hSession, NativeLong hObject);
    public static native int C_GetObjectSize(NativeLong hSession, NativeLong hObject, NativeLongByReference pulSize);
    public static native int C_GetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public static native int C_SetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public static native int C_FindObjectsInit(NativeLong hSession, Template pTemplate, NativeLong ulCount);
    public static native int C_FindObjects(NativeLong hSession, LongArray phObject, NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);
    public static native int C_FindObjectsFinal(NativeLong hSession);
    public static native int C_EncryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);
    public static native int C_EncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public static native int C_EncryptFinal(NativeLong hSession, byte[] pLastEncryptedPart, NativeLongByReference pulLastEncryptedPartLen);
    public static native int C_DecryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen, byte[] pData, NativeLongByReference pulDataLen);
    public static native int C_DecryptUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pData, NativeLongByReference pulDataLen);
    public static native int C_DecryptFinal(NativeLong hSession, byte[] pLastPart, NativeLongByReference pulLastPartLen);
    public static native int C_DigestInit(NativeLong hSession, JNA_CKM pMechanism);
    public static native int C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pDigest, NativeLongByReference pulDigestLen);
    public static native int C_DigestUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public static native int C_DigestKey(NativeLong hSession, NativeLong hKey);
    public static native int C_DigestFinal(NativeLong hSession, byte[] pDigest, NativeLongByReference pulDigestLen);
    public static native int C_SignInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public static native int C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public static native int C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public static native int C_SignRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_SignRecover(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public static native int C_VerifyInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLong ulSignatureLen);
    public static native int C_VerifyUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public static native int C_VerifyFinal(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen);
    public static native int C_VerifyRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public static native int C_VerifyRecover(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen, byte[] pData, NativeLongByReference pulDataLen);
    public static native int C_DigestEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public static native int C_DecryptDigestUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public static native int C_SignEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public static native int C_DecryptVerifyUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public static native int C_GenerateKey(NativeLong hSession, JNA_CKM pMechanism, Template pTemplate, NativeLong ulCount, NativeLongByReference phKey);
    public static native int C_GenerateKeyPair(NativeLong hSession, JNA_CKM pMechanism, Template pPublicKeyTemplate, NativeLong ulPublicKeyAttributeCount, Template pPrivateKeyTemplate, NativeLong ulPrivateKeyAttributeCount, NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);
    public static native int C_WrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hWrappingKey, NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);
    public static native int C_UnwrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hUnwrappingKey, byte[] pWrappedKey, NativeLong ulWrappedKeyLen, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public static native int C_DeriveKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hBaseKey, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public static native int C_SeedRandom(NativeLong hSession, byte[] pSeed, NativeLong ulSeedLen);
    public static native int C_GenerateRandom(NativeLong hSession, byte[] pRandom, NativeLong ulRandomLen);
    public static native int C_GetFunctionStatus(NativeLong hSession);
    public static native int C_CancelFunction(NativeLong hSession);
}
