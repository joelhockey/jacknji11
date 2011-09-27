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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * JNA PKCS#11 provider.  Does mapping between jacknji11 structs and
 * JNA structs and calls through to {@link JNANative} native methods.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA implements NativeProvider {

    {
        // set ULong size
        ULong.ULONG_SIZE = NativeLong.SIZE == 4
            ? ULong.ULongSize.ULONG4 : ULong.ULongSize.ULONG8;
    }

    public long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        return JNANative.C_Initialize(new JNA_CK_C_INITIALIZE_ARGS(pInitArgs));
    }

    public long C_Finalize(NativePointer pReserved) {
        return JNANative.C_Finalize(new Pointer(pReserved.getAddress()));
    }

    public long C_GetInfo(CK_INFO pInfo) {
        JNA_CK_INFO jna_pInfo = new JNA_CK_INFO().readFrom(pInfo);
        long rv = JNANative.C_GetInfo(jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetSlotList(boolean tokenPresent, long[] pSlotList, LongRef pulCount) {
        LongArray jna_pSlotList = new LongArray(pSlotList);
        NativeLongByReference jna_pulCount = NLP(pulCount.value);
        long rv = JNANative.C_GetSlotList(tokenPresent ? (byte)1 : (byte)0, jna_pSlotList, jna_pulCount);
        jna_pSlotList.update();
        pulCount.value = jna_pulCount.getValue().longValue();
        return rv;
    }

    public long C_GetSlotInfo(long slotID, CK_SLOT_INFO pInfo) {
        JNA_CK_SLOT_INFO jna_pInfo = new JNA_CK_SLOT_INFO().readFrom(pInfo);
        long rv = JNANative.C_GetSlotInfo(NL(slotID), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo) {
        JNA_CK_TOKEN_INFO jna_pInfo = new JNA_CK_TOKEN_INFO().readFrom(pInfo);
        long rv = JNANative.C_GetTokenInfo(NL(slotID), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved) {
        NativeLongByReference jna_pSlot = NLP(pSlot.value);
        Pointer jna_pReserved = new Pointer(pReserved.getAddress());
        long rv = JNANative.C_WaitForSlotEvent(NL(flags), jna_pSlot, jna_pReserved);
        pSlot.value = jna_pSlot.getValue().longValue();
        pReserved.setAddress(Pointer.nativeValue(jna_pReserved));
        return rv;
    }

    public long C_GetMechanismList(long slotID, long[] pMechanismList, LongRef pulCount) {
        LongArray jna_pMechanismList = new LongArray(pMechanismList);
        NativeLongByReference jna_pulCount = NLP(pulCount.value);
        long rv = JNANative.C_GetMechanismList(NL(slotID), jna_pMechanismList, jna_pulCount);
        jna_pMechanismList.update();
        pulCount.value = jna_pulCount.getValue().longValue();
        return rv;
    }

    public long C_GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO pInfo) {
        JNA_CK_MECHANISM_INFO jna_pInfo = new JNA_CK_MECHANISM_INFO().readFrom(pInfo);
        long rv = JNANative.C_GetMechanismInfo(NL(slotID), NL(type), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_InitToken(long slotID, byte[] pPin, long ulPinLen, byte[] pLabel32) {
        return JNANative.C_InitToken(NL(slotID), pPin, NL(ulPinLen), pLabel32);
    }

    public long C_InitPIN(long hSession, byte[] pPin, long ulPinLen) {
        return JNANative.C_InitPIN(NL(hSession), pPin, NL(ulPinLen));
    }

    public long C_SetPIN(long hSession, byte[] pOldPin, long ulOldLen, byte[] pNewPin, long ulNewLen) {
        return JNANative.C_SetPIN(NL(hSession), pOldPin, NL(ulOldLen), pNewPin, NL(ulNewLen));
    }

    public long C_OpenSession(long slotID, long flags, NativePointer application, final CK_NOTIFY notify, LongRef phSession) {
        Pointer jna_application = new Pointer(application.getAddress());
        JNA_CK_NOTIFY jna_notify = new JNA_CK_NOTIFY() {
            public NativeLong invoke(NativeLong hSession, NativeLong event, Pointer pApplication) {
                return NL(notify.invoke(hSession.longValue(), event.longValue(), new NativePointer(Pointer.nativeValue(pApplication))));
            }
        };
        NativeLongByReference jna_phSession = NLP(phSession.value);
        long rv = JNANative.C_OpenSession(NL(slotID), NL(flags), jna_application, jna_notify, jna_phSession);
        application.setAddress(Pointer.nativeValue(jna_application));
        phSession.value = jna_phSession.getValue().longValue();
        return rv;
    }

    public long C_CloseSession(long hSession) {
        return JNANative.C_CloseSession(NL(hSession));
    }

    public long C_CloseAllSessions(long slotID) {
        return JNANative.C_CloseAllSessions(NL(slotID));
    }

    public long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo) {
        JNA_CK_SESSION_INFO jna_pInfo = new JNA_CK_SESSION_INFO().readFrom(pInfo);
        long rv = JNANative.C_GetSessionInfo(NL(hSession), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetOperationState(long hSession, byte[] pOperationState, LongRef pulOperationStateLen) {
        NativeLongByReference jna_pulOperationStateLen = NLP(pulOperationStateLen.value);
        long rv = JNANative.C_GetOperationState(NL(hSession), pOperationState, jna_pulOperationStateLen);
        pulOperationStateLen.value = jna_pulOperationStateLen.getValue().longValue();
        return rv;
    }

    public long C_SetOperationState(long hSession, byte[] pOperationState, long ulOperationStateLen, long hEncryptionKey,
            long hAuthenticationKey) {
        return JNANative.C_SetOperationState(NL(hSession), pOperationState, NL(ulOperationStateLen),
            NL(hEncryptionKey), NL(hAuthenticationKey));
    }

    public long C_Login(long hSession, long userType, byte[] pPin, long ulPinLen) {
        return JNANative.C_Login(NL(hSession), NL(userType), pPin, NL(ulPinLen));
    }

    public long C_Logout(long hSession) {
        return JNANative.C_Logout(NL(hSession));
    }

    public long C_CreateObject(long hSession, CKA[] pTemplate, long ulCount, LongRef phObject) {
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phObject = NLP(phObject.value);
        long rv = JNANative.C_CreateObject(NL(hSession), jna_pTemplate, NL(ulCount), jna_phObject);
        jna_pTemplate.update();
        phObject.value = jna_phObject.getValue().longValue();
        return rv;
    }

    public long C_CopyObject(long hSession, long hObject, CKA[] pTemplate, long ulCount, LongRef phNewObject) {
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phNewObject = NLP(phNewObject.value);
        long rv = JNANative.C_CopyObject(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount), jna_phNewObject);
        jna_pTemplate.update();
        phNewObject.value = jna_phNewObject.getValue().longValue();
        return rv;
    }

    public long C_DestroyObject(long hSession, long hObject) {
        return JNANative.C_DestroyObject(NL(hSession), NL(hObject));
    }

    public long C_GetObjectSize(long hSession, long hObject, LongRef pulSize) {
        NativeLongByReference jna_pulSize = NLP(pulSize.value);
        long rv = JNANative.C_GetObjectSize(NL(hSession), NL(hObject), jna_pulSize);
        pulSize.value = jna_pulSize.getValue().longValue();
        return rv;
    }

    public long C_GetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Template jna_pTemplate = new Template(pTemplate);
        long rv = JNANative.C_GetAttributeValue(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
        return rv;
    }

    public long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Template jna_pTemplate = new Template(pTemplate);
        long rv = JNANative.C_SetAttributeValue(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
        return rv;
    }

    public long C_FindObjectsInit(long hSession, CKA[] pTemplate, long ulCount) {
        Template jna_pTemplate = new Template(pTemplate);
        long rv = JNANative.C_FindObjectsInit(NL(hSession), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
        return rv;
    }

    public long C_FindObjects(long hSession, long[] phObject, long ulMaxObjectCount, LongRef pulObjectCount) {
        LongArray jna_phObject = new LongArray(phObject);
        NativeLongByReference jna_pulObjectCOunt = NLP(pulObjectCount.value);
        long rv = JNANative.C_FindObjects(NL(hSession), jna_phObject, NL(ulMaxObjectCount), jna_pulObjectCOunt);
        jna_phObject.update();
        pulObjectCount.value = jna_pulObjectCOunt.getValue().longValue();
        return rv;
    }

    public long C_FindObjectsFinal(long hSession) {
        return JNANative.C_FindObjectsFinal(NL(hSession));
    }

    public long C_EncryptInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_EncryptInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_Encrypt(long hSession, byte[] pData, long ulDataLen, byte[] pEncryptedData, LongRef pulEncryptedDataLen) {
        NativeLongByReference jna_pulEncryptedDataLen = NLP(pulEncryptedDataLen.value);
        long rv = JNANative.C_Encrypt(NL(hSession), pData, NL(ulDataLen), pEncryptedData, jna_pulEncryptedDataLen);
        pulEncryptedDataLen.value = jna_pulEncryptedDataLen.getValue().longValue();
        return rv;
    }

    public long C_EncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jna_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JNANative.C_EncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_EncryptFinal(long hSession, byte[] pLastEncryptedPart, LongRef pulLastEncryptedPartLen) {
        NativeLongByReference jna_pulLastEncryptedPartLen = NLP(pulLastEncryptedPartLen.value);
        long rv = JNANative.C_EncryptFinal(NL(hSession), pLastEncryptedPart, jna_pulLastEncryptedPartLen);
        pulLastEncryptedPartLen.value = jna_pulLastEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_DecryptInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_Decrypt(long hSession, byte[] pEncryptedData, long ulEncryptedDataLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = JNANative.C_Decrypt(NL(hSession), pEncryptedData, NL(ulEncryptedDataLen), pData, jna_pulDataLen);
        pulDataLen.value= jna_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = JNANative.C_DecryptUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pData, jna_pulDataLen);
        pulDataLen.value = jna_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptFinal(long hSession, byte[] pLastPart, LongRef pulLastPartLen) {
        NativeLongByReference jna_pulLastPartLen = NLP(pulLastPartLen.value);
        long rv = JNANative.C_DecryptFinal(NL(hSession), pLastPart, jna_pulLastPartLen);
        pulLastPartLen.value = jna_pulLastPartLen.getValue().longValue();
        return rv;
    }

    public long C_DigestInit(long hSession, CKM pMechanism) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_DigestInit(NL(hSession), jna_pMechanism);
    }

    public long C_Digest(long hSession, byte[] pData, long ulDataLen, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jna_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JNANative.C_Digest(NL(hSession), pData, NL(ulDataLen), pDigest, jna_pulDigestLen);
        pulDigestLen.value = jna_pulDigestLen.getValue().longValue();
        return rv;
    }

    public long C_DigestUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JNANative.C_DigestUpdate(NL(hSession), pPart, NL(ulPartLen));
    }

    public long C_DigestKey(long hSession, long hKey) {
        return JNANative.C_DigestKey(NL(hSession), NL(hKey));
    }

    public long C_DigestFinal(long hSession, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jna_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JNANative.C_DigestFinal(NL(hSession), pDigest, jna_pulDigestLen);
        pulDigestLen.value = jna_pulDigestLen.getValue().longValue();
        return rv;
    }

    public long C_SignInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_SignInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_Sign(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JNANative.C_Sign(NL(hSession), pData, NL(ulDataLen), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_SignUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JNANative.C_SignUpdate(NL(hSession), pPart, NL(ulPartLen));
    }

    public long C_SignFinal(long hSession, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JNANative.C_SignFinal(NL(hSession), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_SignRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_SignRecoverInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_SignRecover(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JNANative.C_SignRecover(NL(hSession), pData, NL(ulDataLen), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_VerifyInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_VerifyInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_Verify(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, long ulSignatureLen) {
        return JNANative.C_Verify(NL(hSession), pData, NL(ulDataLen), pSignature, NL(ulSignatureLen));
    }

    public long C_VerifyUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JNANative.C_VerifyUpdate(NL(hSession), pPart, NL(ulPartLen));
    }

    public long C_VerifyFinal(long hSession, byte[] pSignature, long ulSignatureLen) {
        return JNANative.C_VerifyFinal(NL(hSession), pSignature, NL(ulSignatureLen));
    }

    public long C_VerifyRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return JNANative.C_VerifyRecoverInit(NL(hSession), jna_pMechanism, NL(hKey));
    }

    public long C_VerifyRecover(long hSession, byte[] pSignature, long ulSignatureLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = JNANative.C_VerifyRecover(NL(hSession), pSignature, NL(ulSignatureLen), pData, jna_pulDataLen);
        pulDataLen.value = jna_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DigestEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jna_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JNANative.C_DigestEncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jna_pulPartLen = NLP(pulPartLen.value);
        long rv = JNANative.C_DecryptDigestUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pPart, jna_pulPartLen);
        pulPartLen.value = jna_pulPartLen.getValue().longValue();
        return rv;
    }

    public long C_SignEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jna_pulEncryptPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JNANative.C_SignEncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jna_pulPartLen = NLP(pulPartLen.value);
        long rv = JNANative.C_DecryptVerifyUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pPart, jna_pulPartLen);
        pulPartLen.value = jna_pulPartLen.getValue().longValue();
        return rv;
    }

    public long C_GenerateKey(long hSession, CKM pMechanism, CKA[] pTemplate, long ulCount, LongRef phKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = JNANative.C_GenerateKey(NL(hSession), jna_pMechanism, jna_pTemplate, NL(ulCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
        return rv;
    }


    public long C_GenerateKeyPair(long hSession, CKM pMechanism, CKA[] pPublicKeyTemplate, long ulPublicKeyAttributeCount,
            CKA[] pPrivateKeyTemplate, long ulPrivateKeyAttributeCount, LongRef phPublicKey, LongRef phPrivateKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pPublicKeyTemplate = new Template(pPublicKeyTemplate);
        Template jna_pPrivateKeyTemplate = new Template(pPrivateKeyTemplate);
        NativeLongByReference jna_phPublicKey = NLP(phPublicKey.value);
        NativeLongByReference jna_phPrivateKey = NLP(phPrivateKey.value);
        long rv = JNANative.C_GenerateKeyPair(NL(hSession), jna_pMechanism, jna_pPublicKeyTemplate, NL(ulPublicKeyAttributeCount),
            jna_pPrivateKeyTemplate, NL(ulPrivateKeyAttributeCount), jna_phPublicKey, jna_phPrivateKey);
        phPublicKey.value = jna_phPublicKey.getValue().longValue();
        phPrivateKey.value = jna_phPrivateKey.getValue().longValue();
        return rv;
    }

    public long C_WrapKey(long hSession, CKM pMechanism, long hWrappingKey, long hKey, byte[] pWrappedKey, LongRef pulWrappedKeyLen) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        NativeLongByReference jna_pulWrappedKeyLen = NLP(pulWrappedKeyLen.value);
        long rv = JNANative.C_WrapKey(NL(hSession), jna_pMechanism, NL(hWrappingKey), NL(hKey), pWrappedKey, jna_pulWrappedKeyLen);
        pulWrappedKeyLen.value = jna_pulWrappedKeyLen.getValue().longValue();
        return rv;
    }

    public long C_UnwrapKey(long hSession, CKM pMechanism, long hUnwrappingKey, byte[] pWrappedKey, long ulWrappedKeyLen,
            CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = JNANative.C_UnwrapKey(NL(hSession), jna_pMechanism, NL(hUnwrappingKey), pWrappedKey, NL(ulWrappedKeyLen),
            jna_pTemplate, NL(ulAttributeCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
        return rv;
    }

    public long C_DeriveKey(long hSession, CKM pMechanism, long hBaseKey, CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = JNANative.C_DeriveKey(NL(hSession), jna_pMechanism, NL(hBaseKey), jna_pTemplate, NL(ulAttributeCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
        return rv;
    }

    public long C_SeedRandom(long hSession, byte[] pSeed, long ulSeedLen) {
        return JNANative.C_SeedRandom(NL(hSession), pSeed, NL(ulSeedLen));
    }

    public long C_GenerateRandom(long hSession, byte[] pRandomData, long ulRandomLen) {
        return JNANative.C_GenerateRandom(NL(hSession), pRandomData, NL(ulRandomLen));
    }

    public long C_GetFunctionStatus(long hSession) {
        return JNANative.C_GetFunctionStatus(NL(hSession));
    }

    public long C_CancelFunction(long hSession) {
        return JNANative.C_CancelFunction(NL(hSession));
    }

    private static NativeLong NL(long l) { return new NativeLong(l); }
    private static NativeLongByReference NLP(long l) { return new NativeLongByReference(new NativeLong(l)); }
}
