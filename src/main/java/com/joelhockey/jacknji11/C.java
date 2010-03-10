/*
 * Copyright 2010 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 * THIS SOURCE CODE IS PROVIDED BY JOEL HOCKEY WITH A 30-DAY MONEY BACK
 * GUARANTEE.  IF THIS CODE DOES NOT MEAN WHAT IT SAYS IT MEANS WITHIN THE
 * FIRST 30 DAYS, SIMPLY RETURN THIS CODE IN ORIGINAL CONDITION FOR A PARTIAL
 * REFUND.  IN ADDITION, I WILL REFORMAT THIS CODE USING YOUR PREFERRED
 * BRACE-POSITIONING AND INDENTATION.  THIS WARRANTY IS VOID IF THE CODE IS
 * FOUND TO HAVE BEEN COMPILED.  NO FURTHER WARRANTY IS OFFERED.
 */

package com.joelhockey.jacknji11;

import java.util.Arrays;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Low-level java interface that maps to {@link Native} cryptoki calls.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link Native} provides the lowest level JNA direct mapping to the C_* functions.
 * There is little reason why you would ever want to invoke it directly, but you can.
 * <li>{@link C} provides the exact same interface as {@link Native} by
 * calling through to the correspoding native method.  The 'C_' at the start
 * of the function is removed since 'C.' when you call the static methods looks
 * equivalent.  In addition to {@link Native}, {@link C} handles some of the low-level
 * JNA plumbing such as 'pushing' any values changed within the native call back into
 * java objects.  You can use this if you require fine-grain control over something.
 * <li>{@link CE} provides the most user-friendly interface.  It calls the
 * {link C} equivalnt function, and converts any non-zero return values into
 * a {@link CKRException}, and automatically resizes arrays and other helpful things.
 * I recommend that you use it exclusively if possible.
 * </ol>
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class C {
    private static final byte TRUE = 1;
    private static final byte FALSE = 0;

    /**
     * Initialise Cryptoki with null mutexes, and CKF_OS_LOCKING_OK flag set.
     * @see Native#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     */
    public static int Initialize() {
        CK_C_INITIALIZE_ARGS args = new CK_C_INITIALIZE_ARGS(null, null, null, null,
                CK_C_INITIALIZE_ARGS.CKF_OS_LOCKING_OK);
        return Native.C_Initialize(args);
    }

    /**
     * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
     * @see Native#C_Finalize(Pointer)
     * @return {@link CKR} return code
     */
    public static int Finalize() {
        return Native.C_Finalize(null);
    }

    /**
     * C_GetInfo returns general information about Cryptoki. pInfo points to the location that receives the information.
     * @param info location that receives information
     * @return {@link CKR} return code
     * @see Native#C_GetInfo(CK_INFO)
     */
    public static int GetInfo(CK_INFO info) {
        int rv = Native.C_GetInfo(info);
        info.read();
        return rv;
    }

    /**
     *
     * @param tokenPresent
     * @param slotList
     * @param count
     * @return {@link CKR} return code
     * @see Native#C_GetSlotList(byte, LongArray, LongRef)
     */
    public static int GetSlotList(boolean tokenPresent, int[] slotList, LongRef count) {
        LongArray slotsRef = new LongArray(slotList);
        int rv = Native.C_GetSlotList(tokenPresent ? TRUE : FALSE, slotsRef, count);
        slotsRef.update(slotList);
        return rv;
    }

    /**
     *
     * @param slotID
     * @param info
     * @return {@link CKR} return code
     * @see Native#C_GetSlotInfo(NativeLong, CK_SLOT_INFO)
     */
    public static int GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = Native.C_GetSlotInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }

    /**
     *
     * @param slotID
     * @param info
     * @return {@link CKR} return code
     * @see Native#C_GetTokenInfo(NativeLong, CK_TOKEN_INFO)
     */
    public static int GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = Native.C_GetTokenInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }

    /**
     *
     * @param flags
     * @param slot
     * @param reserved
     * @return {@link CKR} return code
     * @see Native#C_WaitForSlotEvent(NativeLong, LongRef, Pointer)
     */
    public static int WaitForSlotEvent(int flags, LongRef slot, Pointer reserved) {
        return Native.C_WaitForSlotEvent(new NativeLong(flags), slot, reserved);
    }

    /**
     *
     * @param slotID
     * @param mechanismList
     * @param count
     * @return {@link CKR} return code
     * @see Native#C_GetMechanismList(NativeLong, LongArray, LongRef)
     */
    public static int GetMechanismList(int slotID, int[] mechanismList, LongRef count) {
        LongArray longArray = new LongArray(mechanismList);
        int rv = Native.C_GetMechanismList(new NativeLong(slotID), longArray, count);
        longArray.update(mechanismList);
        return rv;
    }

    /**
     *
     * @param slotID
     * @param type
     * @param info
     * @return {@link CKR} return code
     * @see Native#C_GetMechanismInfo(NativeLong, NativeLong, CK_MECHANISM_INFO)
     */
    public static int GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        return Native.C_GetMechanismInfo(new NativeLong(slotID), new NativeLong(type), info);
    }

    /**
     *
     * @param slotID
     * @param pin
     * @param label
     * @return {@link CKR} return code
     * @see Native#C_InitToken(NativeLong, byte[], NativeLong, byte[])
     */
    public static int InitToken(int slotID, byte[] pin, byte[] label) {
        byte[] label32;
        if (label != null && label.length == 32) {
            label32 = label;
        } else {
            label32 = new byte[32];
            Arrays.fill(label32, (byte) 0x20); // space fill
            if (label != null) {
                System.arraycopy(label, 0, label32, 0, Math.min(label32.length, label.length));
            }
        }
        return Native.C_InitToken(new NativeLong(slotID), pin, baLen(pin), label32);
    }

    /**
     *
     * @param session the session's handle
     * @param pin
     * @return {@link CKR} return code
     * @see Native#C_InitPIN(NativeLong, byte[], NativeLong)
     */
    public static int InitPIN(int session, byte[] pin) {
        return Native.C_InitPIN(new NativeLong(session), pin, baLen(pin));
    }

    /**
     *
     * @param session the session's handle
     * @param oldPin
     * @param newPin
     * @return {@link CKR} return code
     * @see Native#C_SetPIN(NativeLong, byte[], NativeLong, byte[], NativeLong)
     */
    public static int SetPIN(int session, byte[] oldPin, byte[] newPin) {
        return Native.C_SetPIN(new NativeLong(session), oldPin, baLen(oldPin), newPin, baLen(newPin));
    }

    /**
     *
     * @param slotID
     * @param flags
     * @param application
     * @param notify
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_OpenSession(NativeLong, NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        return Native.C_OpenSession(new NativeLong(slotID), new NativeLong(flags), application, notify, session);
    }

    /**
     *
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_CloseSession(NativeLong)
     */
    public static int CloseSession(int session) {
        return Native.C_CloseSession(new NativeLong(session));
    }

    /**
     *
     * @param slotID
     * @return {@link CKR} return code
     * @see Native#C_CloseAllSessions(NativeLong)
     */
    public static int CloseAllSessions(int slotID) {
        return Native.C_CloseAllSessions(new NativeLong(slotID));
    }

    /**
     *
     * @param session the session's handle
     * @param info
     * @return {@link CKR} return code
     * @see Native#C_GetSessionInfo(NativeLong, CK_SESSION_INFO)
     */
    public static int GetSessionInfo(int session, CK_SESSION_INFO info) {
        return Native.C_GetSessionInfo(new NativeLong(session), info);
    }

    /**
     *
     * @param session the session's handle
     * @param operationState
     * @param operationStateLen
     * @return {@link CKR} return code
     * @see Native#C_GetOperationState(NativeLong, byte[], LongRef)
     */
    public static int GetOperationState(int session, byte[] operationState, LongRef operationStateLen) {
        return Native.C_GetOperationState(new NativeLong(session), operationState, operationStateLen);
    }

    /**
     *
     * @param session the session's handle
     * @param operationState
     * @param encryptionKey
     * @param authenticationKey
     * @return {@link CKR} return code
     * @see Native#C_SetOperationState(NativeLong, byte[], NativeLong, NativeLong, NativeLong)
     */
    public static int SetOperationState(int session, byte[] operationState,
            int encryptionKey, int authenticationKey) {

        return Native.C_SetOperationState(new NativeLong(session), operationState, baLen(operationState),
                new NativeLong(encryptionKey), new NativeLong(authenticationKey));
    }

    /**
     *
     * @param session the session's handle
     * @param userType
     * @param pin
     * @return {@link CKR} return code
     * @see Native#C_Login(NativeLong, NativeLong, byte[], NativeLong)
     */
    public static int Login(int session, int userType, byte[] pin) {
        return Native.C_Login(new NativeLong(session), new NativeLong(userType), pin, baLen(pin));
    }

    /**
     *
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_Logout(NativeLong)
     */
    public static int Logout(int session) {
        return Native.C_Logout(new NativeLong(session));
    }

    /**
     *
     * @param session the session's handle
     * @param templ
     * @param object
     * @return {@link CKR} return code
     * @see Native#C_CreateObject(NativeLong, Template, NativeLong, LongRef)
     */
    public static int CreateObject(int session, CKA[] templ, LongRef object) {
        return Native.C_CreateObject(new NativeLong(session), new Template(templ), attLen(templ), object);
    }

    /**
     *
     * @param session the session's handle
     * @param object
     * @param templ
     * @param newObject
     * @return {@link CKR} return code
     * @see Native#C_CopyObject(NativeLong, NativeLong, Template, NativeLong, LongRef)
     */
    public static int CopyObject(int session, int object, CKA[] templ, LongRef newObject) {
        return Native.C_CopyObject(new NativeLong(session), new NativeLong(object),
                new Template(templ), attLen(templ), newObject);
    }

    /**
     *
     * @param session the session's handle
     * @param object
     * @return {@link CKR} return code
     * @see Native#C_DestroyObject(NativeLong, NativeLong)
     */
    public static int DestroyObject(int session, int object) {
        return Native.C_DestroyObject(new NativeLong(session), new NativeLong(object));
    }

    /**
     *
     * @param session the session's handle
     * @param object
     * @param size
     * @return {@link CKR} return code
     * @see Native#C_GetObjectSize(NativeLong, NativeLong, LongRef)
     */
    public static int GetObjectSize(int session, int object, LongRef size) {
        return Native.C_GetObjectSize(new NativeLong(session), new NativeLong(object), size);
    }

    /**
     *
     * @param session the session's handle
     * @param object
     * @param templ
     * @return {@link CKR} return code
     * @see Native#C_GetAttributeValue(NativeLong, NativeLong, Template, NativeLong)
     */
    public static int GetAttributeValue(int session, int object, CKA[] templ) {
        Template template = new Template(templ);
        int rv = Native.C_GetAttributeValue(new NativeLong(session), new NativeLong(object), template, attLen(templ));
        template.update(templ);
        return rv;
    }

    /**
     *
     * @param session the session's handle
     * @param object
     * @param templ
     * @return {@link CKR} return code
     * @see Native#C_SetAttributeValue(NativeLong, NativeLong, Template, NativeLong)
     */
    public static int SetAttributeValue(int session, int object, CKA[] templ) {
        return Native.C_SetAttributeValue(new NativeLong(session), new NativeLong(object),
                new Template(templ), attLen(templ));
    }

    /**
     *
     * @param session the session's handle
     * @param templ
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsInit(NativeLong, Template, NativeLong)
     */
    public static int FindObjectsInit(int session, CKA[] templ) {
        return Native.C_FindObjectsInit(new NativeLong(session), new Template(templ), attLen(templ));
    }

    /**
     *
     * @param session the session's handle
     * @param found
     * @param objectCount
     * @return {@link CKR} return code
     * @see Native#C_FindObjects(NativeLong, LongArray, NativeLong, LongRef)
     */
    public static int FindObjects(int session, int[] found, LongRef objectCount) {
        LongArray longArray = new LongArray(found);
        int rv = Native.C_FindObjects(new NativeLong(session), longArray,
                new NativeLong(found == null ? 0 : found.length), objectCount);
        longArray.update(found);
        return rv;
    }

    /**
     *
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsFinal(NativeLong)
     */
    public static int FindObjectsFinal(int session) {
        return Native.C_FindObjectsFinal(new NativeLong(session));
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_EncryptInit(NativeLong, CKM, NativeLong)
     */
    public static int EncryptInit(int session, CKM mechanism, int key) {
        return Native.C_EncryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param data
     * @param encryptedData
     * @param encryptedDataLen
     * @return {@link CKR} return code
     * @see Native#C_Encrypt(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Encrypt(int session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        return Native.C_Encrypt(new NativeLong(session), data, baLen(data), encryptedData, encryptedDataLen);
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @param encryptedPart
     * @param encryptedPartLen
     * @return {@link CKR} return code
     * @see Native#C_EncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int EncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return Native.C_EncryptUpdate(new NativeLong(session), part, baLen(part), encryptedPart, encryptedPartLen);
    }

    /**
     *
     * @param session the session's handle
     * @param lastEncryptedPart
     * @param lastEncryptedPartLen
     * @return {@link CKR} return code
     * @see Native#C_EncryptFinal(NativeLong, byte[], LongRef)
     */
    public static int EncryptFinal(int session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        return Native.C_EncryptFinal(new NativeLong(session), lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_DecryptInit(NativeLong, CKM, NativeLong)
     */
    public static int DecryptInit(int session, CKM mechanism, int key) {
        return Native.C_DecryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param encryptedData
     * @param data
     * @param dataLen
     * @return {@link CKR} return code
     * @see Native#C_Decrypt(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Decrypt(int session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        return Native.C_Decrypt(new NativeLong(session), encryptedData, baLen(encryptedData), data, dataLen);
    }

    /**
     *
     * @param session the session's handle
     * @param encryptedPart
     * @param data
     * @param dataLen
     * @return {@link CKR} return code
     * @see Native#C_DecryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptUpdate(int session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        return Native.C_DecryptUpdate(new NativeLong(session), encryptedPart, baLen(encryptedPart), data, dataLen);
    }

    /**
     *
     * @param session the session's handle
     * @param lastPart
     * @param lastPartLen
     * @return {@link CKR} return code
     * @see Native#C_DecryptFinal(NativeLong, byte[], LongRef)
     */
    public static int DecryptFinal(int session, byte[] lastPart, LongRef lastPartLen) {
        return Native.C_DecryptFinal(new NativeLong(session), lastPart, lastPartLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @return {@link CKR} return code
     * @see Native#C_DigestInit(NativeLong, CKM)
     */
    public static int DigestInit(int session, CKM mechanism) {
        return Native.C_DigestInit(new NativeLong(session), mechanism);
    }

    /**
     *
     * @param session the session's handle
     * @param data
     * @param digest
     * @param digestLen
     * @return {@link CKR} return code
     * @see Native#C_Digest(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Digest(int session, byte[] data, byte[] digest, LongRef digestLen) {
        return Native.C_Digest(new NativeLong(session), data, baLen(data), digest, digestLen);
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @return {@link CKR} return code
     * @see Native#C_DigestUpdate(NativeLong, byte[], NativeLong)
     */
    public static int DigestUpdate(int session, byte[] part) {
        return Native.C_DigestUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     *
     * @param session the session's handle
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_DigestKey(NativeLong, NativeLong)
     */
    public static int DigestKey(int session, int key) {
        return Native.C_DigestKey(new NativeLong(session), new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param digest
     * @param digestLen
     * @return {@link CKR} return code
     * @see Native#C_DigestFinal(NativeLong, byte[], LongRef)
     */
    public static int DigestFinal(int session, byte[] digest, LongRef digestLen) {
        return Native.C_DigestFinal(new NativeLong(session), digest, digestLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_SignInit(NativeLong, CKM, NativeLong)
     */
    public static int SignInit(int session, CKM mechanism, int key) {
        return Native.C_SignInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param data
     * @param signature
     * @param signatureLen
     * @return {@link CKR} return code
     * @see Native#C_Sign(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Sign(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        return Native.C_Sign(new NativeLong(session), data, baLen(data), signature, signatureLen);
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @return {@link CKR} return code
     * @see Native#C_SignUpdate(NativeLong, byte[], NativeLong)
     */
    public static int SignUpdate(int session, byte[] part) {
        return Native.C_SignUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     *
     * @param session the session's handle
     * @param signature
     * @param signatureLen
     * @return {@link CKR} return code
     * @see Native#C_SignFinal(NativeLong, byte[], LongRef)
     */
    public static int SignFinal(int session, byte[] signature, LongRef signatureLen) {
        return Native.C_SignFinal(new NativeLong(session), signature, signatureLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_SignRecoverInit(NativeLong, CKM, NativeLong)
     */
    public static int SignRecoverInit(int session, CKM mechanism, int key) {
        return Native.C_SignRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param data
     * @param signature
     * @param signatureLen
     * @return {@link CKR} return code
     * @see Native#C_SignRecover(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int SignRecover(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        return Native.C_SignRecover(new NativeLong(session), data, baLen(data), signature, signatureLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_VerifyInit(NativeLong, CKM, NativeLong)
     */
    public static int VerifyInit(int session, CKM mechanism, int key) {
        return Native.C_VerifyInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param data
     * @param signature
     * @return {@link CKR} return code
     * @see Native#C_Verify(NativeLong, byte[], NativeLong, byte[], NativeLong)
     */
    public static int Verify(int session, byte[] data, byte[] signature) {
        return Native.C_Verify(new NativeLong(session), data, baLen(data), signature, baLen(signature));
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @return {@link CKR} return code
     * @see Native#C_VerifyUpdate(NativeLong, byte[], NativeLong)
     */
    public static int VerifyUpdate(int session, byte[] part) {
        return Native.C_VerifyUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     *
     * @param session the session's handle
     * @param signature
     * @return {@link CKR} return code
     * @see Native#C_VerifyFinal(NativeLong, byte[], NativeLong)
     */
    public static int VerifyFinal(int session, byte[] signature) {
        return Native.C_VerifyFinal(new NativeLong(session), signature, baLen(signature));
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_VerifyRecoverInit(NativeLong, CKM, NativeLong)
     */
    public static int VerifyRecoverInit(int session, CKM mechanism, int key) {
        return Native.C_VerifyRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     *
     * @param session the session's handle
     * @param signature
     * @param data
     * @param dataLen
     * @return {@link CKR} return code
     * @see Native#C_VerifyRecover(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int VerifyRecover(int session, byte[] signature, byte[] data, LongRef dataLen) {
        return Native.C_VerifyRecover(new NativeLong(session), signature, baLen(signature), data, dataLen);
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @param encryptedPart
     * @param encryptedPartLen
     * @return {@link CKR} return code
     * @see Native#C_DigestEncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DigestEncryptUpdate(int session, byte[] part, byte[] encryptedPart,
            LongRef encryptedPartLen) {

        return Native.C_DigestEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
    }

    /**
     *
     * @param session the session's handle
     * @param encryptedPart
     * @param part
     * @param partLen
     * @return {@link CKR} return code
     * @see Native#C_DecryptDigestUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptDigestUpdate(int session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        return Native.C_DecryptDigestUpdate(new NativeLong(session),
                encryptedPart, baLen(encryptedPart), part, partLen);
    }

    /**
     *
     * @param session the session's handle
     * @param part
     * @param encryptedPart
     * @param encryptedPartLen
     * @return {@link CKR} return code
     * @see Native#C_SignEncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int SignEncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return Native.C_SignEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
    }

    /**
     *
     * @param session the session's handle
     * @param encrypedPart
     * @param part
     * @param partLen
     * @return {@link CKR} return code
     * @see Native#C_DecryptVerifyUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptVerifyUpdate(int session, byte[] encrypedPart, byte[] part, LongRef partLen) {
        return Native.C_DecryptVerifyUpdate(new NativeLong(session),
                encrypedPart, baLen(encrypedPart), part, partLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param templ
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_GenerateKey(NativeLong, CKM, Template, NativeLong, LongRef)
     */
    public static int GenerateKey(int session, CKM mechanism, CKA[] templ, LongRef key) {
        return Native.C_GenerateKey(new NativeLong(session), mechanism, new Template(templ), attLen(templ), key);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param publicKeyTemplate
     * @param privateKeyTemplate
     * @param publicKey
     * @param privateKey
     * @return {@link CKR} return code
     * @see Native#C_GenerateKeyPair(NativeLong, CKM, Template, NativeLong, Template, NativeLong, LongRef, LongRef)
     */
    public static int GenerateKeyPair(int session, CKM mechanism, CKA[] publicKeyTemplate,
            CKA[] privateKeyTemplate, LongRef publicKey, LongRef privateKey) {

        return Native.C_GenerateKeyPair(new NativeLong(session), mechanism,
                new Template(publicKeyTemplate), attLen(publicKeyTemplate),
                new Template(privateKeyTemplate), attLen(privateKeyTemplate), publicKey, privateKey);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism
     * @param wrappingKey
     * @param key
     * @param wrappedKey
     * @param wrappedKeyLen
     * @return {@link CKR} return code
     * @see Native#C_WrapKey(NativeLong, CKM, NativeLong, NativeLong, byte[], LongRef)
     */
    public static int WrapKey(int session, CKM mechanism, int wrappingKey, int key,
            byte[] wrappedKey, LongRef wrappedKeyLen) {

        return Native.C_WrapKey(new NativeLong(session), mechanism, new NativeLong(wrappingKey),
                new NativeLong(key), wrappedKey, wrappedKeyLen);
    }

    /**
     *
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param unwrappingKey
     * @param wrappedKey
     * @param templ
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_UnwrapKey(NativeLong, CKM, NativeLong, byte[], NativeLong, Template, NativeLong, LongRef)
     */
    public static int UnwrapKey(int session, CKM mechanism, int unwrappingKey, byte[] wrappedKey,
            CKA[] templ, LongRef key) {

        return Native.C_UnwrapKey(new NativeLong(session), mechanism, new NativeLong(unwrappingKey),
                wrappedKey, baLen(wrappedKey), new Template(templ), attLen(templ), key);
    }

    /**
     * C_DeriveKey derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism
     * @param baseKey
     * @param templ
     * @param key
     * @return {@link CKR} return code
     * @see Native#C_DeriveKey(NativeLong, CKM, NativeLong, Template, NativeLong, LongRef)
     */
    public static int DeriveKey(int session, CKM mechanism, int baseKey, CKA[] templ, LongRef key) {
        return Native.C_DeriveKey(new NativeLong(session), mechanism, new NativeLong(baseKey),
                new Template(templ), attLen(templ), key);
    }

    /**
     * C_SeedRandom mixes additional seed material into the token’s random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @return {@link CKR} return code
     * @see Native#C_SeedRandom(NativeLong, byte[], NativeLong)
     */
    public static int SeedRandom(int session, byte[] seed) {
        return Native.C_SeedRandom(new NativeLong(session), seed, baLen(seed));
    }

    /**
     * C_GenerateRandom generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @return {@link CKR} return code
     * @see Native#C_GenerateRandom(NativeLong, byte[], NativeLong)
     */
    public static int GenerateRandom(int session, byte[] randomData) {
        return Native.C_GenerateRandom(new NativeLong(session), randomData, baLen(randomData));
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_GetFunctionStatus(NativeLong)
     */
    public static int GetFunctionStatus(int session) {
        return Native.C_GetFunctionStatus(new NativeLong(session));
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_CancelFunction(NativeLong)
     */
    public static int CancelFunction(int session) {
        return Native.C_CancelFunction(new NativeLong(session));
    }

    /**
     * Return length of buf (0 if buf is null).
     * @param buf buf
     * @return length of buf (0 if buf is null)
     */
    private static NativeLong baLen(byte[] buf) {
        return new NativeLong(buf == null ? 0 : buf.length);
    }

    /**
     * Return length of template (0 if templ is null).
     * @param templ template
     * @return length of template (0 if templ is null)
     */
    private static NativeLong attLen(CKA[] templ) {
        return new NativeLong(templ == null ? 0 : templ.length);
    }
}
