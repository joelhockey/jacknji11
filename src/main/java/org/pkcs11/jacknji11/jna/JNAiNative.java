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

import com.sun.jna.Library;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * JNA Native class with direct mapped methods.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public interface JNAiNative extends Library {
    
    int C_Initialize(JNA_CK_C_INITIALIZE_ARGS pInitArgs);
    int C_Finalize(Pointer pReserved);
    int C_GetInfo(JNA_CK_INFO pInfo);
    int C_GetSlotList(byte tokenPresent, LongArray pSlotList, NativeLongByReference pulCount);
    int C_GetSlotInfo(NativeLong slotID, JNA_CK_SLOT_INFO pInfo);
    int C_GetTokenInfo(NativeLong slotID, JNA_CK_TOKEN_INFO pInfo);
    int C_WaitForSlotEvent(NativeLong flags, NativeLongByReference pSlot, Pointer pReserved);
    int C_GetMechanismList(NativeLong slotID, LongArray pMechanismList, NativeLongByReference pulCount);
    int C_GetMechanismInfo(NativeLong slotID, NativeLong type, JNA_CK_MECHANISM_INFO pInfo);
    int C_InitToken(NativeLong slotID, byte[] pPin, NativeLong ulPinLen, byte[] pLabel32);
    int C_InitPIN(NativeLong hSession, byte[] pPin, NativeLong ulPinLen);
    int C_SetPIN(NativeLong hSession, byte[] pOldPin, NativeLong ulOldLen, byte[] pNewPin, NativeLong ulNewLen);
    int C_OpenSession(NativeLong slotID, NativeLong flags, Pointer application, JNA_CK_NOTIFY notify, NativeLongByReference phSession);
    int C_CloseSession(NativeLong hSession);
    int C_CloseAllSessions(NativeLong slotID);
    int C_GetSessionInfo(NativeLong hSession, JNA_CK_SESSION_INFO pInfo);
    int C_GetOperationState(NativeLong hSession, byte[] pOperationState, NativeLongByReference pulOperationStateLen);
    int C_SetOperationState(NativeLong hSession, byte[] pOperationState, NativeLong ulOperationStateLen, NativeLong hEncryptionKey, NativeLong hAuthenticationKey);
    int C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);
    int C_Logout(NativeLong hSession);
    int C_CreateObject(NativeLong hSession, Template pTemplate, NativeLong ulCount, NativeLongByReference phObject);
    int C_CopyObject(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount, NativeLongByReference phNewObject);
    int C_DestroyObject(NativeLong hSession, NativeLong hObject);
    int C_GetObjectSize(NativeLong hSession, NativeLong hObject, NativeLongByReference pulSize);
    int C_GetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    int C_SetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    int C_FindObjectsInit(NativeLong hSession, Template pTemplate, NativeLong ulCount);
    int C_FindObjects(NativeLong hSession, LongArray phObject, NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);
    int C_FindObjectsFinal(NativeLong hSession);
    int C_EncryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);
    int C_EncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    int C_EncryptFinal(NativeLong hSession, byte[] pLastEncryptedPart, NativeLongByReference pulLastEncryptedPartLen);
    int C_DecryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen, byte[] pData, NativeLongByReference pulDataLen);
    int C_DecryptUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pData, NativeLongByReference pulDataLen);
    int C_DecryptFinal(NativeLong hSession, byte[] pLastPart, NativeLongByReference pulLastPartLen);
    int C_DigestInit(NativeLong hSession, JNA_CKM pMechanism);
    int C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pDigest, NativeLongByReference pulDigestLen);
    int C_DigestUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    int C_DigestKey(NativeLong hSession, NativeLong hKey);
    int C_DigestFinal(NativeLong hSession, byte[] pDigest, NativeLongByReference pulDigestLen);
    int C_SignInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    int C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    int C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);
    int C_SignRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_SignRecover(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    int C_VerifyInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLong ulSignatureLen);
    int C_VerifyUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    int C_VerifyFinal(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen);
    int C_VerifyRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    int C_VerifyRecover(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen, byte[] pData, NativeLongByReference pulDataLen);
    int C_DigestEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    int C_DecryptDigestUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    int C_SignEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    int C_DecryptVerifyUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    int C_GenerateKey(NativeLong hSession, JNA_CKM pMechanism, Template pTemplate, NativeLong ulCount, NativeLongByReference phKey);
    int C_GenerateKeyPair(NativeLong hSession, JNA_CKM pMechanism, Template pPublicKeyTemplate, NativeLong ulPublicKeyAttributeCount, Template pPrivateKeyTemplate, NativeLong ulPrivateKeyAttributeCount, NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);
    int C_WrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hWrappingKey, NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);
    int C_UnwrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hUnwrappingKey, byte[] pWrappedKey, NativeLong ulWrappedKeyLen, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    int C_DeriveKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hBaseKey, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    int C_SeedRandom(NativeLong hSession, byte[] pSeed, NativeLong ulSeedLen);
    int C_GenerateRandom(NativeLong hSession, byte[] pRandom, NativeLong ulRandomLen);
    int C_GetFunctionStatus(NativeLong hSession);
    int C_CancelFunction(NativeLong hSession);
}
