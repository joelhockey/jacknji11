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

package org.pkcs11.jacknji11.jni;

import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CK_NOTIFY;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.LongRef;
import org.pkcs11.jacknji11.NativePointer;
import org.pkcs11.jacknji11.NativeProvider;
import org.pkcs11.jacknji11.ULong;

public class JNI implements NativeProvider {
    static {
        System.loadLibrary("jacknji11");
        init();
        ULong.ULONG_SIZE = ULongSize() == 4 ? ULong.ULongSize.ULONG4 : ULong.ULongSize.ULONG8;
    }

    public static native void init();
    public static native int ULongSize();
    public native long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs);
    public native long C_Finalize(NativePointer pReserved);
    public native long C_GetInfo(CK_INFO pInfo);
    public native long C_GetSlotList(boolean tokenPresent, long[] pSlotList, LongRef pulCount);
    public native long C_GetSlotInfo(long slotID, CK_SLOT_INFO pInfo);
    public native long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo);
    public native long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved);
    public native long C_GetMechanismList(long slotID, long[] pMechanismList, LongRef pulCount);
    public native long C_GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO pInfo);
    public native long C_InitToken(long slotID, byte[] pPin, long ulPinLen, byte[] pLabel32);
    public native long C_InitPIN(long hSession, byte[] pPin, long ulPinLen);
    public native long C_SetPIN(long hSession, byte[] pOldPin, long ulOldLen, byte[] pNewPin, long ulNewLen);
    public native long C_OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef phSession);
    public native long C_CloseSession(long hSession);
    public native long C_CloseAllSessions(long slotID);
    public native long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo);
    public native long C_GetOperationState(long hSession, byte[] pOperationState, LongRef pulOperationStateLen);
    public native long C_SetOperationState(long hSession, byte[] pOperationState, long ulOperationStateLen, long hEncryptionKey, long hAuthenticationKey);
    public native long C_Login(long hSession, long userType, byte[] pPin, long ulPinLen);
    public native long C_Logout(long hSession);
    public native long C_CreateObject(long hSession, CKA[] pTemplate, long ulCount, LongRef phObject);
    public native long C_CopyObject(long hSession, long hObject, CKA[] pTemplate, long ulCount, LongRef phNewObject);
    public native long C_DestroyObject(long hSession, long hObject);
    public native long C_GetObjectSize(long hSession, long hObject, LongRef pulSize);
    public native long C_GetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount);
    public native long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount);
    public native long C_FindObjectsInit(long hSession, CKA[] pTemplate, long ulCount);
    public native long C_FindObjects(long hSession, long[] phObject, long ulMaxObjectCount, LongRef pulObjectCount);
    public native long C_FindObjectsFinal(long hSession);
    public native long C_EncryptInit(long hSession, CKM pMechanism, long hKey);
    public native long C_Encrypt(long hSession, byte[] pData, long ulDataLen, byte[] pEncryptedData, LongRef pulEncryptedDataLen);
    public native long C_EncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);
    public native long C_EncryptFinal(long hSession, byte[] pLastEncryptedPart, LongRef pulLastEncryptedPartLen);
    public native long C_DecryptInit(long hSession, CKM pMechanism, long hKey);
    public native long C_Decrypt(long hSession, byte[] pEncryptedData, long ulEncryptedDataLen, byte[] pData, LongRef pulDataLen);
    public native long C_DecryptUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pData, LongRef pulDataLen);
    public native long C_DecryptFinal(long hSession, byte[] pLastPart, LongRef pulLastPartLen);
    public native long C_DigestInit(long hSession, CKM pMechanism);
    public native long C_Digest(long hSession, byte[] pData, long ulDataLen, byte[] pDigest, LongRef pulDigestLen);
    public native long C_DigestUpdate(long hSession, byte[] pPart, long ulPartLen);
    public native long C_DigestKey(long hSession, long hKey);
    public native long C_DigestFinal(long hSession, byte[] pDigest, LongRef pulDigestLen);
    public native long C_SignInit(long hSession, CKM pMechanism, long hKey);
    public native long C_Sign(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen);
    public native long C_SignUpdate(long hSession, byte[] pPart, long ulPartLen);
    public native long C_SignFinal(long hSession, byte[] pSignature, LongRef pulSignatureLen);
    public native long C_SignRecoverInit(long hSession, CKM pMechanism, long hKey);
    public native long C_SignRecover(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen);
    public native long C_VerifyInit(long hSession, CKM pMechanism, long hKey);
    public native long C_Verify(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, long ulSignatureLen);
    public native long C_VerifyUpdate(long hSession, byte[] pPart, long ulPartLen);
    public native long C_VerifyFinal(long hSession, byte[] pSignature, long ulSignatureLen);
    public native long C_VerifyRecoverInit(long hSession, CKM pMechanism, long hKey);
    public native long C_VerifyRecover(long hSession, byte[] pSignature, long ulSignatureLen, byte[] pData, LongRef pulDataLen);
    public native long C_DigestEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);
    public native long C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen);
    public native long C_SignEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen);
    public native long C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen);
    public native long C_GenerateKey(long hSession, CKM pMechanism, CKA[] pTemplate, long ulCount, LongRef phKey);
    public native long C_GenerateKeyPair(long hSession, CKM pMechanism, CKA[] pPublicKeyTemplate, long ulPublicKeyAttributeCount, CKA[] pPrivateKeyTemplate, long ulPrivateKeyAttributeCount, LongRef phPublicKey, LongRef phPrivateKey);
    public native long C_WrapKey(long hSession, CKM pMechanism, long hWrappingKey, long hKey, byte[] pWrappedKey, LongRef pulWrappedKeyLen);
    public native long C_UnwrapKey(long hSession, CKM pMechanism, long hUnwrappingKey, byte[] pWrappedKey, long ulWrappedKeyLen, CKA[] pTemplate, long ulAttributeCount, LongRef phKey);
    public native long C_DeriveKey(long hSession, CKM pMechanism, long hBaseKey, CKA[] pTemplate, long ulAttributeCount, LongRef phKey);
    public native long C_SeedRandom(long hSession, byte[] pSeed, long ulSeedLen);
    public native long C_GenerateRandom(long hSession, byte[] pRandom, long ulRandomLen);
    public native long C_GetFunctionStatus(long hSession);
    public native long C_CancelFunction(long hSession);
}
