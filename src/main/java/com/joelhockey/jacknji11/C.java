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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

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
     * Initialise Cryptoki with supplied args.
     * @see Native#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     */
    public static int Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        return Native.C_Initialize(pInitArgs);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see Native#C_Finalize(Pointer)
     * @return {@link CKR} return code
     */
    public static int Finalize() {
        return Native.C_Finalize(null);
    }

    /**
     * Returns general information about Cryptoki.
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
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
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
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @return {@link CKR} return code
     * @see Native#C_GetSlotInfo(NativeLong, CK_SLOT_INFO)
     */
    public static int GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = Native.C_GetSlotInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @return {@link CKR} return code
     * @see Native#C_GetTokenInfo(NativeLong, CK_TOKEN_INFO)
     */
    public static int GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = Native.C_GetTokenInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param reserved reserved.  Should be null
     * @return {@link CKR} return code
     * @see Native#C_WaitForSlotEvent(NativeLong, LongRef, Pointer)
     */
    public static int WaitForSlotEvent(int flags, LongRef slot, Pointer reserved) {
        return Native.C_WaitForSlotEvent(new NativeLong(flags), slot, reserved);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
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
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @return {@link CKR} return code
     * @see Native#C_GetMechanismInfo(NativeLong, NativeLong, CK_MECHANISM_INFO)
     */
    public static int GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        return Native.C_GetMechanismInfo(new NativeLong(slotID), new NativeLong(type), info);
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's intital PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
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
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @return {@link CKR} return code
     * @see Native#C_InitPIN(NativeLong, byte[], NativeLong)
     */
    public static int InitPIN(int session, byte[] pin) {
        return Native.C_InitPIN(new NativeLong(session), pin, baLen(pin));
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @return {@link CKR} return code
     * @see Native#C_SetPIN(NativeLong, byte[], NativeLong, byte[], NativeLong)
     */
    public static int SetPIN(int session, byte[] oldPin, byte[] newPin) {
        return Native.C_SetPIN(new NativeLong(session), oldPin, baLen(oldPin), newPin, baLen(newPin));
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param session gets session handle
     * @return {@link CKR} return code
     * @see Native#C_OpenSession(NativeLong, NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        return Native.C_OpenSession(new NativeLong(slotID), new NativeLong(flags), application, notify, session);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_CloseSession(NativeLong)
     */
    public static int CloseSession(int session) {
        return Native.C_CloseSession(new NativeLong(session));
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see Native#C_CloseAllSessions(NativeLong)
     */
    public static int CloseAllSessions(int slotID) {
        return Native.C_CloseAllSessions(new NativeLong(slotID));
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @return {@link CKR} return code
     * @see Native#C_GetSessionInfo(NativeLong, CK_SESSION_INFO)
     */
    public static int GetSessionInfo(int session, CK_SESSION_INFO info) {
        return Native.C_GetSessionInfo(new NativeLong(session), info);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @return {@link CKR} return code
     * @see Native#C_GetOperationState(NativeLong, byte[], LongRef)
     */
    public static int GetOperationState(int session, byte[] operationState, LongRef operationStateLen) {
        return Native.C_GetOperationState(new NativeLong(session), operationState, operationStateLen);
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @return {@link CKR} return code
     * @see Native#C_SetOperationState(NativeLong, byte[], NativeLong, NativeLong, NativeLong)
     */
    public static int SetOperationState(int session, byte[] operationState,
            int encryptionKey, int authenticationKey) {

        return Native.C_SetOperationState(new NativeLong(session), operationState, baLen(operationState),
                new NativeLong(encryptionKey), new NativeLong(authenticationKey));
    }

    /**
     * Logs a user into a token.
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @return {@link CKR} return code
     * @see Native#C_Login(NativeLong, NativeLong, byte[], NativeLong)
     */
    public static int Login(int session, int userType, byte[] pin) {
        return Native.C_Login(new NativeLong(session), new NativeLong(userType), pin, baLen(pin));
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_Logout(NativeLong)
     */
    public static int Logout(int session) {
        return Native.C_Logout(new NativeLong(session));
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @return {@link CKR} return code
     * @see Native#C_CreateObject(NativeLong, Template, NativeLong, LongRef)
     */
    public static int CreateObject(int session, CKA[] templ, LongRef object) {
        return Native.C_CreateObject(new NativeLong(session), new Template(templ), attLen(templ), object);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @return {@link CKR} return code
     * @see Native#C_CopyObject(NativeLong, NativeLong, Template, NativeLong, LongRef)
     */
    public static int CopyObject(int session, int object, CKA[] templ, LongRef newObject) {
        return Native.C_CopyObject(new NativeLong(session), new NativeLong(object),
                new Template(templ), attLen(templ), newObject);
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @return {@link CKR} return code
     * @see Native#C_DestroyObject(NativeLong, NativeLong)
     */
    public static int DestroyObject(int session, int object) {
        return Native.C_DestroyObject(new NativeLong(session), new NativeLong(object));
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @return {@link CKR} return code
     * @see Native#C_GetObjectSize(NativeLong, NativeLong, LongRef)
     */
    public static int GetObjectSize(int session, int object, LongRef size) {
        return Native.C_GetObjectSize(new NativeLong(session), new NativeLong(object), size);
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
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
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attriutes and values
     * @return {@link CKR} return code
     * @see Native#C_SetAttributeValue(NativeLong, NativeLong, Template, NativeLong)
     */
    public static int SetAttributeValue(int session, int object, CKA[] templ) {
        return Native.C_SetAttributeValue(new NativeLong(session), new NativeLong(object),
                new Template(templ), attLen(templ));
    }

    /**
     * Initailses a search for token and sesion objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsInit(NativeLong, Template, NativeLong)
     */
    public static int FindObjectsInit(int session, CKA[] templ) {
        return Native.C_FindObjectsInit(new NativeLong(session), new Template(templ), attLen(templ));
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
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
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsFinal(NativeLong)
     */
    public static int FindObjectsFinal(int session) {
        return Native.C_FindObjectsFinal(new NativeLong(session));
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @return {@link CKR} return code
     * @see Native#C_EncryptInit(NativeLong, CKM, NativeLong)
     */
    public static int EncryptInit(int session, CKM mechanism, int key) {
        return Native.C_EncryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @return {@link CKR} return code
     * @see Native#C_Encrypt(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Encrypt(int session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        return Native.C_Encrypt(new NativeLong(session), data, baLen(data), encryptedData, encryptedDataLen);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @return {@link CKR} return code
     * @see Native#C_EncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int EncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return Native.C_EncryptUpdate(new NativeLong(session), part, baLen(part), encryptedPart, encryptedPartLen);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @return {@link CKR} return code
     * @see Native#C_EncryptFinal(NativeLong, byte[], LongRef)
     */
    public static int EncryptFinal(int session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        return Native.C_EncryptFinal(new NativeLong(session), lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     * Intialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @return {@link CKR} return code
     * @see Native#C_DecryptInit(NativeLong, CKM, NativeLong)
     */
    public static int DecryptInit(int session, CKM mechanism, int key) {
        return Native.C_DecryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @return {@link CKR} return code
     * @see Native#C_Decrypt(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Decrypt(int session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        return Native.C_Decrypt(new NativeLong(session), encryptedData, baLen(encryptedData), data, dataLen);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @return {@link CKR} return code
     * @see Native#C_DecryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptUpdate(int session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        return Native.C_DecryptUpdate(new NativeLong(session), encryptedPart, baLen(encryptedPart), data, dataLen);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @return {@link CKR} return code
     * @see Native#C_DecryptFinal(NativeLong, byte[], LongRef)
     */
    public static int DecryptFinal(int session, byte[] lastPart, LongRef lastPartLen) {
        return Native.C_DecryptFinal(new NativeLong(session), lastPart, lastPartLen);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @return {@link CKR} return code
     * @see Native#C_DigestInit(NativeLong, CKM)
     */
    public static int DigestInit(int session, CKM mechanism) {
        return Native.C_DigestInit(new NativeLong(session), mechanism);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @return {@link CKR} return code
     * @see Native#C_Digest(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Digest(int session, byte[] data, byte[] digest, LongRef digestLen) {
        return Native.C_Digest(new NativeLong(session), data, baLen(data), digest, digestLen);
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @return {@link CKR} return code
     * @see Native#C_DigestUpdate(NativeLong, byte[], NativeLong)
     */
    public static int DigestUpdate(int session, byte[] part) {
        return Native.C_DigestUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @return {@link CKR} return code
     * @see Native#C_DigestKey(NativeLong, NativeLong)
     */
    public static int DigestKey(int session, int key) {
        return Native.C_DigestKey(new NativeLong(session), new NativeLong(key));
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @return {@link CKR} return code
     * @see Native#C_DigestFinal(NativeLong, byte[], LongRef)
     */
    public static int DigestFinal(int session, byte[] digest, LongRef digestLen) {
        return Native.C_DigestFinal(new NativeLong(session), digest, digestLen);
    }

    /**
     * Initialises a signature (private key encryption) operation, where
     * the signature is (will be) an appendix to the data, and plaintext
     * cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @return {@link CKR} return code
     * @see Native#C_SignInit(NativeLong, CKM, NativeLong)
     */
    public static int SignInit(int session, CKM mechanism, int key) {
        return Native.C_SignInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see Native#C_Sign(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int Sign(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        return Native.C_Sign(new NativeLong(session), data, baLen(data), signature, signatureLen);
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @return {@link CKR} return code
     * @see Native#C_SignUpdate(NativeLong, byte[], NativeLong)
     */
    public static int SignUpdate(int session, byte[] part) {
        return Native.C_SignUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see Native#C_SignFinal(NativeLong, byte[], LongRef)
     */
    public static int SignFinal(int session, byte[] signature, LongRef signatureLen) {
        return Native.C_SignFinal(new NativeLong(session), signature, signatureLen);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @return {@link CKR} return code
     * @see Native#C_SignRecoverInit(NativeLong, CKM, NativeLong)
     */
    public static int SignRecoverInit(int session, CKM mechanism, int key) {
        return Native.C_SignRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see Native#C_SignRecover(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int SignRecover(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        return Native.C_SignRecover(new NativeLong(session), data, baLen(data), signature, signatureLen);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @return {@link CKR} return code
     * @see Native#C_VerifyInit(NativeLong, CKM, NativeLong)
     */
    public static int VerifyInit(int session, CKM mechanism, int key) {
        return Native.C_VerifyInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @return {@link CKR} return code
     * @see Native#C_Verify(NativeLong, byte[], NativeLong, byte[], NativeLong)
     */
    public static int Verify(int session, byte[] data, byte[] signature) {
        return Native.C_Verify(new NativeLong(session), data, baLen(data), signature, baLen(signature));
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @return {@link CKR} return code
     * @see Native#C_VerifyUpdate(NativeLong, byte[], NativeLong)
     */
    public static int VerifyUpdate(int session, byte[] part) {
        return Native.C_VerifyUpdate(new NativeLong(session), part, baLen(part));
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return {@link CKR} return code
     * @see Native#C_VerifyFinal(NativeLong, byte[], NativeLong)
     */
    public static int VerifyFinal(int session, byte[] signature) {
        return Native.C_VerifyFinal(new NativeLong(session), signature, baLen(signature));
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @return {@link CKR} return code
     * @see Native#C_VerifyRecoverInit(NativeLong, CKM, NativeLong)
     */
    public static int VerifyRecoverInit(int session, CKM mechanism, int key) {
        return Native.C_VerifyRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @return {@link CKR} return code
     * @see Native#C_VerifyRecover(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int VerifyRecover(int session, byte[] signature, byte[] data, LongRef dataLen) {
        return Native.C_VerifyRecover(new NativeLong(session), signature, baLen(signature), data, dataLen);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @return {@link CKR} return code
     * @see Native#C_DigestEncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DigestEncryptUpdate(int session, byte[] part, byte[] encryptedPart,
            LongRef encryptedPartLen) {

        return Native.C_DigestEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @return {@link CKR} return code
     * @see Native#C_DecryptDigestUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptDigestUpdate(int session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        return Native.C_DecryptDigestUpdate(new NativeLong(session),
                encryptedPart, baLen(encryptedPart), part, partLen);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @return {@link CKR} return code
     * @see Native#C_SignEncryptUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int SignEncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return Native.C_SignEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encrypedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @return {@link CKR} return code
     * @see Native#C_DecryptVerifyUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptVerifyUpdate(int session, byte[] encrypedPart, byte[] part, LongRef partLen) {
        return Native.C_DecryptVerifyUpdate(new NativeLong(session),
                encrypedPart, baLen(encrypedPart), part, partLen);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @return {@link CKR} return code
     * @see Native#C_GenerateKey(NativeLong, CKM, Template, NativeLong, LongRef)
     */
    public static int GenerateKey(int session, CKM mechanism, CKA[] templ, LongRef key) {
        return Native.C_GenerateKey(new NativeLong(session), mechanism, new Template(templ), attLen(templ), key);
    }

    /**
     * Generates a public-key / private-key pair, create new key objects.
     * @param session the session's handle
     * @param mechanism key generation mechansim
     * @param publicKeyTemplate template for the new public key
     * @param privateKeyTemplate template for the new private key
     * @param publicKey gets handle of new public key
     * @param privateKey gets handle of new private key
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
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @param wrappedKey gets wrapped key
     * @param wrappedKeyLen gets wrapped key length
     * @return {@link CKR} return code
     * @see Native#C_WrapKey(NativeLong, CKM, NativeLong, NativeLong, byte[], LongRef)
     */
    public static int WrapKey(int session, CKM mechanism, int wrappingKey, int key,
            byte[] wrappedKey, LongRef wrappedKeyLen) {

        return Native.C_WrapKey(new NativeLong(session), mechanism, new NativeLong(wrappingKey),
                new NativeLong(key), wrappedKey, wrappedKeyLen);
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @param key gets new handle
     * @return {@link CKR} return code
     * @see Native#C_UnwrapKey(NativeLong, CKM, NativeLong, byte[], NativeLong, Template, NativeLong, LongRef)
     */
    public static int UnwrapKey(int session, CKM mechanism, int unwrappingKey, byte[] wrappedKey,
            CKA[] templ, LongRef key) {

        return Native.C_UnwrapKey(new NativeLong(session), mechanism, new NativeLong(unwrappingKey),
                wrappedKey, baLen(wrappedKey), new Template(templ), attLen(templ), key);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @param key ges new handle
     * @return {@link CKR} return code
     * @see Native#C_DeriveKey(NativeLong, CKM, NativeLong, Template, NativeLong, LongRef)
     */
    public static int DeriveKey(int session, CKM mechanism, int baseKey, CKA[] templ, LongRef key) {
        return Native.C_DeriveKey(new NativeLong(session), mechanism, new NativeLong(baseKey),
                new Template(templ), attLen(templ), key);
    }

    /**
     * Mixes additional seed material into the token’s random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @return {@link CKR} return code
     * @see Native#C_SeedRandom(NativeLong, byte[], NativeLong)
     */
    public static int SeedRandom(int session, byte[] seed) {
        return Native.C_SeedRandom(new NativeLong(session), seed, baLen(seed));
    }

    /**
     * Generates random or pseudo-random data.
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

    /**
     * Helper method.  Adds all public static final int fields in c to map, mapping field value to name.
     * @param c class
     * @param map map to hold value:name
     */
    public static Map<Integer, String> i2s(Class c) {
        Map<Integer, String> map = new HashMap<Integer, String>();
        try {
            for (Field f : c.getDeclaredFields()) {
                // only put 'public static final int' in map
                if (f.getType() == int.class && Modifier.isPublic(f.getModifiers())
                        && Modifier.isStatic(f.getModifiers()) && Modifier.isFinal(f.getModifiers())) {
                    map.put(f.getInt(null), f.getName());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return map;
    }

    /**
     * Helper method, Maps i to constant name, or value 'unknown %s constant 0x08x' % (ckx, i)'.
     * @param map I2S map
     * @param ckx prefix of constant type, e.g. 'CKA'
     * @param i constant value
     * @return constant name, or value 'unknown %s constant 0x08x' % (ckx, i)'.
     */
    public static String i2s(Map<Integer, String> map, String ckx, int i) {
        String s = map.get(i);
        if (s != null) {
            return s;
        } else {
          return String.format("unknown %s constant 0x%08x", ckx, i);
        }
    }

    /**
     * Helper method.  String format of flags.
     * @param i2s i2s map
     * @param flags flags
     * @return string format of flags
     */
    public static String f2s(Map<Integer, String> i2s, int flags) {
        StringBuilder sb = new StringBuilder("(");
        String sep = "";
        for (int i = 31; i >= 0; i--) {
            if ((flags & (1 << i)) != 0) {
                sb.append(sep);
                sb.append(C.i2s(i2s, "CKF", 1 << i));
                sep = "|";
            }
        }
        sb.append(")");
        return sb.toString();
    }
}
