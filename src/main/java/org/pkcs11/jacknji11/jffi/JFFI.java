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
import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;

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

/**
 * JFFI PKCS#11 Provider.  Does mapping between jacknji11 structs and JFFI
 * structs and calls through to {@link JFFINative}.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI implements NativeProvider {

    {
        // set ULong size
        ULong.ULONG_SIZE = jnr.ffi.Runtime.getSystemRuntime().longSize() == 4
            ? ULong.ULongSize.ULONG4 : ULong.ULongSize.ULONG8;
    }

    public long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        return JFFINative.C_Initialize(new JFFI_CK_C_INITIALIZE_ARGS(pInitArgs));
    }

    public long C_Finalize(NativePointer pReserved) {
        return JFFINative.C_Finalize(Address.valueOf(pReserved.getAddress()));
    }

    public long C_GetInfo(CK_INFO pInfo) {
        JFFI_CK_INFO jffi_pInfo = new JFFI_CK_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetInfo(jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetSlotList(boolean tokenPresent, long[] pSlotList, LongRef pulCount) {
        NativeLongByReference jffi_pulCount = NLP(pulCount.value);
        long rv = JFFINative.C_GetSlotList(tokenPresent, pSlotList, jffi_pulCount);
        pulCount.value = jffi_pulCount.getValue().longValue();
        return rv;
    }

    public long C_GetSlotInfo(long slotID, CK_SLOT_INFO pInfo) {
        JFFI_CK_SLOT_INFO jffi_pInfo = new JFFI_CK_SLOT_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetSlotInfo(slotID, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo) {
        JFFI_CK_TOKEN_INFO jffi_pInfo = new JFFI_CK_TOKEN_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetTokenInfo(slotID, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved) {
        NativeLongByReference jffi_pSlot = NLP(pSlot.value);
        Address jffi_pReserved = Address.valueOf(pReserved.getAddress());
        long rv = JFFINative.C_WaitForSlotEvent(flags, jffi_pSlot, jffi_pReserved);
        pSlot.value = jffi_pSlot.getValue().longValue();
        pReserved.setAddress(jffi_pReserved.address());
        return rv;
    }

    public long C_GetMechanismList(long slotID, long[] pMechanismList, LongRef pulCount) {
        NativeLongByReference jffi_pulCount = NLP(pulCount.value);
        long rv = JFFINative.C_GetMechanismList(slotID, pMechanismList, jffi_pulCount);
        pulCount.value = jffi_pulCount.getValue().longValue();
        return rv;
    }

    public long C_GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO pInfo) {
        JFFI_CK_MECHANISM_INFO jffi_pInfo = new JFFI_CK_MECHANISM_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetMechanismInfo(slotID, type, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_InitToken(long slotID, byte[] pPin, long ulPinLen, byte[] pLabel32) {
        return JFFINative.C_InitToken(slotID, pPin, ulPinLen, pLabel32);
    }

    public long C_InitPIN(long hSession, byte[] pPin, long ulPinLen) {
        return JFFINative.C_InitPIN(hSession, pPin, ulPinLen);
    }

    public long C_SetPIN(long hSession, byte[] pOldPin, long ulOldLen, byte[] pNewPin, long ulNewLen) {
        return JFFINative.C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
    }

    public long C_OpenSession(long slotID, long flags, NativePointer application, final CK_NOTIFY notify, LongRef phSession) {
        Address jffi_application = Address.valueOf(application.getAddress());
        JFFI_CK_NOTIFY jffi_notify = new JFFI_CK_NOTIFY() {
            public long invoke(long hSession, long event, Pointer pApplication) {
                return notify.invoke(hSession, event, new NativePointer(pApplication.address()));
            }
        };
        NativeLongByReference jffi_phSession = NLP(phSession.value);
//        long rv = JFFINative.C_OpenSession(slotID, flags, jffi_application, jffi_notify, jffi_phSession);
long rv = JFFINative.C_OpenSession(slotID, flags, jffi_application, null, jffi_phSession);
        application.setAddress(jffi_application.address());
        phSession.value = jffi_phSession.getValue().longValue();
        return rv;
    }

    public long C_CloseSession(long hSession) {
        return JFFINative.C_CloseSession(hSession);
    }

    public long C_CloseAllSessions(long slotID) {
        return JFFINative.C_CloseAllSessions(slotID);
    }

    public long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo) {
        JFFI_CK_SESSION_INFO jffi_pInfo = new JFFI_CK_SESSION_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetSessionInfo(hSession, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    public long C_GetOperationState(long hSession, byte[] pOperationState, LongRef pulOperationStateLen) {
        NativeLongByReference jffi_pulOperationStateLen = NLP(pulOperationStateLen.value);
        long rv = JFFINative.C_GetOperationState(hSession, pOperationState, jffi_pulOperationStateLen);
        pulOperationStateLen.value = jffi_pulOperationStateLen.getValue().longValue();
        return rv;
    }

    public long C_SetOperationState(long hSession, byte[] pOperationState, long ulOperationStateLen, long hEncryptionKey,
            long hAuthenticationKey) {
        return JFFINative.C_SetOperationState(hSession, pOperationState, ulOperationStateLen,
            hEncryptionKey, hAuthenticationKey);
    }

    public long C_Login(long hSession, long userType, byte[] pPin, long ulPinLen) {
        return JFFINative.C_Login(hSession, userType, pPin, ulPinLen);
    }

    public long C_Logout(long hSession) {
        return JFFINative.C_Logout(hSession);
    }

    public long C_CreateObject(long hSession, CKA[] pTemplate, long ulCount, LongRef phObject) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phObject = NLP(phObject.value);
        long rv = JFFINative.C_CreateObject(hSession, jffi_pTemplate, ulCount, jffi_phObject);
        phObject.value = jffi_phObject.getValue().longValue();
        return rv;
    }

    public long C_CopyObject(long hSession, long hObject, CKA[] pTemplate, long ulCount, LongRef phNewObject) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phNewObject = NLP(phNewObject.value);
        long rv = JFFINative.C_CopyObject(hSession, hObject, jffi_pTemplate, ulCount, jffi_phNewObject);
        phNewObject.value = jffi_phNewObject.getValue().longValue();
        return rv;
    }

    public long C_DestroyObject(long hSession, long hObject) {
        return JFFINative.C_DestroyObject(hSession, hObject);
    }

    public long C_GetObjectSize(long hSession, long hObject, LongRef pulSize) {
        NativeLongByReference jffi_pulSize = NLP(pulSize.value);
        long rv = JFFINative.C_GetObjectSize(hSession, hObject, jffi_pulSize);
        pulSize.value = jffi_pulSize.getValue().longValue();
        return rv;
    }

    public long C_GetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_GetAttributeValue(hSession, hObject, jffi_pTemplate, ulCount);
        Template.update(jffi_pTemplate, pTemplate);
        return rv;
    }

    public long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_SetAttributeValue(hSession, hObject, jffi_pTemplate, ulCount);
        return rv;
    }

    public long C_FindObjectsInit(long hSession, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_FindObjectsInit(hSession, jffi_pTemplate, ulCount);
        return rv;
    }

    public long C_FindObjects(long hSession, long[] phObject, long ulMaxObjectCount, LongRef pulObjectCount) {
        NativeLongByReference jffi_pulObjectCount = NLP(pulObjectCount.value);
        long rv = JFFINative.C_FindObjects(hSession, phObject, ulMaxObjectCount, jffi_pulObjectCount);
        pulObjectCount.value = jffi_pulObjectCount.getValue().longValue();
        return rv;
    }

    public long C_FindObjectsFinal(long hSession) {
        return JFFINative.C_FindObjectsFinal(hSession);
    }

    public long C_EncryptInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_EncryptInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_Encrypt(long hSession, byte[] pData, long ulDataLen, byte[] pEncryptedData, LongRef pulEncryptedDataLen) {
        NativeLongByReference jffi_pulEncryptedDataLen = NLP(pulEncryptedDataLen.value);
        long rv = JFFINative.C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, jffi_pulEncryptedDataLen);
        pulEncryptedDataLen.value = jffi_pulEncryptedDataLen.getValue().longValue();
        return rv;
    }

    public long C_EncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_EncryptFinal(long hSession, byte[] pLastEncryptedPart, LongRef pulLastEncryptedPartLen) {
        NativeLongByReference jffi_pulLastEncryptedPartLen = NLP(pulLastEncryptedPartLen.value);
        long rv = JFFINative.C_EncryptFinal(hSession, pLastEncryptedPart, jffi_pulLastEncryptedPartLen);
        pulLastEncryptedPartLen.value = jffi_pulLastEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_DecryptInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_Decrypt(long hSession, byte[] pEncryptedData, long ulEncryptedDataLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, jffi_pulDataLen);
        pulDataLen.value= jffi_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pData, jffi_pulDataLen);
        pulDataLen.value = jffi_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptFinal(long hSession, byte[] pLastPart, LongRef pulLastPartLen) {
        NativeLongByReference jffi_pulLastPartLen = NLP(pulLastPartLen.value);
        long rv = JFFINative.C_DecryptFinal(hSession, pLastPart, jffi_pulLastPartLen);
        pulLastPartLen.value = jffi_pulLastPartLen.getValue().longValue();
        return rv;
    }

    public long C_DigestInit(long hSession, CKM pMechanism) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_DigestInit(hSession, jffi_pMechanism);
    }

    public long C_Digest(long hSession, byte[] pData, long ulDataLen, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jffi_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JFFINative.C_Digest(hSession, pData, ulDataLen, pDigest, jffi_pulDigestLen);
        pulDigestLen.value = jffi_pulDigestLen.getValue().longValue();
        return rv;
    }

    public long C_DigestUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_DigestUpdate(hSession, pPart, ulPartLen);
    }

    public long C_DigestKey(long hSession, long hKey) {
        return JFFINative.C_DigestKey(hSession, hKey);
    }

    public long C_DigestFinal(long hSession, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jffi_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JFFINative.C_DigestFinal(hSession, pDigest, jffi_pulDigestLen);
        pulDigestLen.value = jffi_pulDigestLen.getValue().longValue();
        return rv;
    }

    public long C_SignInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_SignInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_Sign(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_Sign(hSession, pData, ulDataLen, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_SignUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_SignUpdate(hSession, pPart, ulPartLen);
    }

    public long C_SignFinal(long hSession, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_SignFinal(hSession, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_SignRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_SignRecoverInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_SignRecover(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_SignRecover(hSession, pData, ulDataLen, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }

    public long C_VerifyInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_VerifyInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_Verify(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, long ulSignatureLen) {
        return JFFINative.C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
    }

    public long C_VerifyUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_VerifyUpdate(hSession, pPart, ulPartLen);
    }

    public long C_VerifyFinal(long hSession, byte[] pSignature, long ulSignatureLen) {
        return JFFINative.C_VerifyFinal(hSession, pSignature, ulSignatureLen);
    }

    public long C_VerifyRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_VerifyRecoverInit(hSession, jffi_pMechanism, hKey);
    }

    public long C_VerifyRecover(long hSession, byte[] pSignature, long ulSignatureLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, jffi_pulDataLen);
        pulDataLen.value = jffi_pulDataLen.getValue().longValue();
        return rv;
    }

    public long C_DigestEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jffi_pulPartLen = NLP(pulPartLen.value);
        long rv = JFFINative.C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, jffi_pulPartLen);
        pulPartLen.value = jffi_pulPartLen.getValue().longValue();
        return rv;
    }

    public long C_SignEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptPartLen.getValue().longValue();
        return rv;
    }

    public long C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jffi_pulPartLen = NLP(pulPartLen.value);
        long rv = JFFINative.C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, jffi_pulPartLen);
        pulPartLen.value = jffi_pulPartLen.getValue().longValue();
        return rv;
    }

    public long C_GenerateKey(long hSession, CKM pMechanism, CKA[] pTemplate, long ulCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_GenerateKey(hSession, jffi_pMechanism, jffi_pTemplate, ulCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }


    public long C_GenerateKeyPair(long hSession, CKM pMechanism, CKA[] pPublicKeyTemplate, long ulPublicKeyAttributeCount,
            CKA[] pPrivateKeyTemplate, long ulPrivateKeyAttributeCount, LongRef phPublicKey, LongRef phPrivateKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pPublicKeyTemplate = Template.templ(pPublicKeyTemplate);
        Pointer jffi_pPrivateKeyTemplate = Template.templ(pPrivateKeyTemplate);
        NativeLongByReference jffi_phPublicKey = NLP(phPublicKey.value);
        NativeLongByReference jffi_phPrivateKey = NLP(phPrivateKey.value);
        long rv = JFFINative.C_GenerateKeyPair(hSession, jffi_pMechanism, jffi_pPublicKeyTemplate, ulPublicKeyAttributeCount,
            jffi_pPrivateKeyTemplate, ulPrivateKeyAttributeCount, jffi_phPublicKey, jffi_phPrivateKey);
        phPublicKey.value = jffi_phPublicKey.getValue().longValue();
        phPrivateKey.value = jffi_phPrivateKey.getValue().longValue();
        return rv;
    }

    public long C_WrapKey(long hSession, CKM pMechanism, long hWrappingKey, long hKey, byte[] pWrappedKey, LongRef pulWrappedKeyLen) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        NativeLongByReference jffi_pulWrappedKeyLen = NLP(pulWrappedKeyLen.value);
        long rv = JFFINative.C_WrapKey(hSession, jffi_pMechanism, hWrappingKey, hKey, pWrappedKey, jffi_pulWrappedKeyLen);
        pulWrappedKeyLen.value = jffi_pulWrappedKeyLen.getValue().longValue();
        return rv;
    }

    public long C_UnwrapKey(long hSession, CKM pMechanism, long hUnwrappingKey, byte[] pWrappedKey, long ulWrappedKeyLen,
            CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_UnwrapKey(hSession, jffi_pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen,
            jffi_pTemplate, ulAttributeCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }

    public long C_DeriveKey(long hSession, CKM pMechanism, long hBaseKey, CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_DeriveKey(hSession, jffi_pMechanism, hBaseKey, jffi_pTemplate, ulAttributeCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }

    public long C_SeedRandom(long hSession, byte[] pSeed, long ulSeedLen) {
        return JFFINative.C_SeedRandom(hSession, pSeed, ulSeedLen);
    }

    public long C_GenerateRandom(long hSession, byte[] pRandomData, long ulRandomLen) {
        return JFFINative.C_GenerateRandom(hSession, pRandomData, ulRandomLen);
    }

    public long C_GetFunctionStatus(long hSession) {
        return JFFINative.C_GetFunctionStatus(hSession);
    }

    public long C_CancelFunction(long hSession) {
        return JFFINative.C_CancelFunction(hSession);
    }

    private static NativeLongByReference NLP(long l) { return new NativeLongByReference(l); }
}
