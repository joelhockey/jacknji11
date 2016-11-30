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
public interface JNANativeI extends com.sun.jna.Library {

    public int C_Initialize(JNA_CK_C_INITIALIZE_ARGS pInitArgs);
    public int C_Finalize(Pointer pReserved);
    public int C_GetInfo(JNA_CK_INFO pInfo);
    public int C_GetSlotList(byte tokenPresent, LongArray pSlotList, NativeLongByReference pulCount);
    public int C_GetSlotInfo(NativeLong slotID, JNA_CK_SLOT_INFO pInfo);
    public int C_GetTokenInfo(NativeLong slotID, JNA_CK_TOKEN_INFO pInfo);
    public int C_WaitForSlotEvent(NativeLong flags, NativeLongByReference pSlot, Pointer pReserved);
    public int C_GetMechanismList(NativeLong slotID, LongArray pMechanismList, NativeLongByReference pulCount);
    public int C_GetMechanismInfo(NativeLong slotID, NativeLong type, JNA_CK_MECHANISM_INFO pInfo);
    public int C_InitToken(NativeLong slotID, byte[] pPin, NativeLong ulPinLen, byte[] pLabel32);
    public int C_InitPIN(NativeLong hSession, byte[] pPin, NativeLong ulPinLen);
    public int C_SetPIN(NativeLong hSession, byte[] pOldPin, NativeLong ulOldLen, byte[] pNewPin, NativeLong ulNewLen);
    public int C_OpenSession(NativeLong slotID, NativeLong flags, Pointer application, JNA_CK_NOTIFY notify, NativeLongByReference phSession);
    public int C_CloseSession(NativeLong hSession);
    public int C_CloseAllSessions(NativeLong slotID);
    public int C_GetSessionInfo(NativeLong hSession, JNA_CK_SESSION_INFO pInfo);
    public int C_GetOperationState(NativeLong hSession, byte[] pOperationState, NativeLongByReference pulOperationStateLen);
    public int C_SetOperationState(NativeLong hSession, byte[] pOperationState, NativeLong ulOperationStateLen, NativeLong hEncryptionKey, NativeLong hAuthenticationKey);
    public int C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);
    public int C_Logout(NativeLong hSession);
    public int C_CreateObject(NativeLong hSession, Template pTemplate, NativeLong ulCount, NativeLongByReference phObject);
    public int C_CopyObject(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount, NativeLongByReference phNewObject);
    public int C_DestroyObject(NativeLong hSession, NativeLong hObject);
    public int C_GetObjectSize(NativeLong hSession, NativeLong hObject, NativeLongByReference pulSize);
    public int C_GetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public int C_SetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public int C_FindObjectsInit(NativeLong hSession, Template pTemplate, NativeLong ulCount);
    public int C_FindObjects(NativeLong hSession, LongArray phObject, NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);
    public int C_FindObjectsFinal(NativeLong hSession);
    public int C_EncryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);
    public int C_EncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_EncryptFinal(NativeLong hSession, byte[] pLastEncryptedPart, NativeLongByReference pulLastEncryptedPartLen);
    public int C_DecryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DecryptUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DecryptFinal(NativeLong hSession, byte[] pLastPart, NativeLongByReference pulLastPartLen);
    public int C_DigestInit(NativeLong hSession, JNA_CKM pMechanism);
    public int C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pDigest, NativeLongByReference pulDigestLen);
    public int C_DigestUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_DigestKey(NativeLong hSession, NativeLong hKey);
    public int C_DigestFinal(NativeLong hSession, byte[] pDigest, NativeLongByReference pulDigestLen);
    public int C_SignInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_SignRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_SignRecover(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_VerifyInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLong ulSignatureLen);
    public int C_VerifyUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_VerifyFinal(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen);
    public int C_VerifyRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_VerifyRecover(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DigestEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_DecryptDigestUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public int C_SignEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_DecryptVerifyUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public int C_GenerateKey(NativeLong hSession, JNA_CKM pMechanism, Template pTemplate, NativeLong ulCount, NativeLongByReference phKey);
    public int C_GenerateKeyPair(NativeLong hSession, JNA_CKM pMechanism, Template pPublicKeyTemplate, NativeLong ulPublicKeyAttributeCount, Template pPrivateKeyTemplate, NativeLong ulPrivateKeyAttributeCount, NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);
    public int C_WrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hWrappingKey, NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);
    public int C_UnwrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hUnwrappingKey, byte[] pWrappedKey, NativeLong ulWrappedKeyLen, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public int C_DeriveKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hBaseKey, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public int C_SeedRandom(NativeLong hSession, byte[] pSeed, NativeLong ulSeedLen);
    public int C_GenerateRandom(NativeLong hSession, byte[] pRandom, NativeLong ulRandomLen);
    public int C_GetFunctionStatus(NativeLong hSession);
    public int C_CancelFunction(NativeLong hSession);
}
