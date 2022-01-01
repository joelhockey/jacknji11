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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.pkcs11.jacknji11.jna.JNA;

/**
 * Low-level java interface that maps to {@link NativeProvider} cryptoki calls.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link org.pkcs11.jacknji11.NativeProvider} provides the lowest level
 * direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link org.pkcs11.jacknji11.C} provides the exact same functions
 * as {@link org.pkcs11.jacknji11.NativeProvider} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'C.'</code> when you call the
 * static methods of this class looks similar.  In addition to calling
 * the native methods, {@link org.pkcs11.jacknji11.C} provides logging
 * through apache commons logging.  You can use this if you require fine-grain
 * control over something such as checking
 * {@link org.pkcs11.jacknji11.CKR} return codes.
 * <li>{@link org.pkcs11.jacknji11.CE} (<b>C</b>ryptoki
 * with <b>E</b>xceptions) provides the most user-friendly interface
 * and is the preferred interface to use.  It calls
 * related function(s) in {@link org.pkcs11.jacknji11.C},
 * and converts any non-zero return values into a
 * {@link org.pkcs11.jacknji11.CKRException}.  It automatically resizes
 * arrays and other helpful things.
 * </ol>
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 * @deprecated Use the {@link Ci} class instead
 */
@Deprecated
public class C {

    /**
     * @deprecated Use the {@link Ci} class instead.
     */
    @Deprecated
    static NativeProvider NATIVE;

    /**
     * Initialise Cryptoki with null mutexes, and CKF_OS_LOCKING_OK flag set.
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     * @deprecated use {@link Ci#Initialize()} instead
     */
    @Deprecated
    public static long Initialize() {
        CK_C_INITIALIZE_ARGS args = new CK_C_INITIALIZE_ARGS(null, null, null, null,
                CK_C_INITIALIZE_ARGS.CKF_OS_LOCKING_OK);
        return Initialize(args);
    }

    /**
     * Initialise Cryptoki with supplied args.
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     * @deprecated use {@link Ci#Initialize(CK_C_INITIALIZE_ARGS)} instead
     */
    @Deprecated
    public static long Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        if (NATIVE == null) {
            NATIVE = new JNA();
        }
        return NC.Initialize(NATIVE, pInitArgs);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see NativeProvider#C_Finalize(NativePointer)
     * @return {@link CKR} return code
     * @deprecated use {@link Ci#Finalize()} instead
     */
    @Deprecated
    public static long Finalize() {
        return NC.Finalize(NATIVE);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetInfo(CK_INFO)
     * @deprecated use {@link Ci#GetInfo(CK_INFO)} instead
     */
    @Deprecated
    public static long GetInfo(CK_INFO info) {
        return NC.GetInfo(NATIVE, info);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @deprecated use {@link Ci#GetSlotList(boolean, long[], LongRef)} instead
     */
    @Deprecated
    public static long GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        return NC.GetSlotList(NATIVE, tokenPresent, slotList, count);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     * @deprecated use {@link Ci#GetSlotInfo(long, CK_SLOT_INFO)} instead
     */
    @Deprecated
    public static long GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        return NC.GetSlotInfo(NATIVE, slotID, info);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     * @deprecated use {@link Ci#GetTokenInfo(long, CK_TOKEN_INFO)} instead
     */
    @Deprecated
    public static long GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        return NC.GetTokenInfo(NATIVE, slotID, info);
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param reserved reserved.  Should be null
     * @return {@link CKR} return code
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     * @deprecated use {@link Ci#WaitForSlotEvent(long, LongRef, NativePointer)} instead
     */
    @Deprecated
    public static long WaitForSlotEvent(long flags, LongRef slot, NativePointer reserved) {
        return NC.WaitForSlotEvent(NATIVE, flags, slot, reserved);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     * @deprecated use {@link Ci#GetMechanismList(long, long[], LongRef)} instead
     */
    @Deprecated
    public static long GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        return NC.GetMechanismList(NATIVE, slotID, mechanismList, count);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @deprecated use {@link Ci#GetMechanismInfo(long, long, CK_MECHANISM_INFO)} instead
     */
    @Deprecated
    public static long GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        return NC.GetMechanismInfo(NATIVE, slotID, type, info);
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's initial PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     * @deprecated use {@link Ci#InitToken(long, byte[], byte[])} instead
     */
    @Deprecated
    public static long InitToken(long slotID, byte[] pin, byte[] label) {
        return NC.InitToken(NATIVE, slotID, pin, label);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     * @deprecated use {@link Ci#InitPIN(long, byte[])} instead
     */
    @Deprecated
    public static long InitPIN(long session, byte[] pin) {
        return NC.InitPIN(NATIVE, session, pin);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     * @deprecated use {@link Ci#SetPIN(long, byte[], byte[])} instead
     */
    @Deprecated
    public static long SetPIN(long session, byte[] oldPin, byte[] newPin) {
        return NC.SetPIN(NATIVE, session, oldPin, newPin);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param session gets session handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @deprecated use {@link Ci#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)} instead
     */
    @Deprecated
    public static long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        return NC.OpenSession(NATIVE, slotID, flags, application, notify, session);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseSession(long)
     * @deprecated use {@link Ci#CloseSession(long)} instead
     */
    @Deprecated
    public static long CloseSession(long session) {
        return NC.CloseSession(NATIVE, session);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseAllSessions(long)
     * @deprecated use {@link Ci#CloseAllSessions(long)} instead
     */
    @Deprecated
    public static long CloseAllSessions(long slotID) {
        return NC.CloseAllSessions(NATIVE, slotID);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     * @deprecated use {@link Ci#GetSessionInfo(long, CK_SESSION_INFO)} instead
     */
    @Deprecated
    public static long GetSessionInfo(long session, CK_SESSION_INFO info) {
        return NC.GetSessionInfo(NATIVE, session, info);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     * @deprecated use {@link Ci#GetOperationState(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        return NC.GetOperationState(NATIVE, session, operationState, operationStateLen);
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     * @deprecated use {@link Ci#SetOperationState(long, byte[], long, long)} instead
     */
    @Deprecated
    public static long SetOperationState(long session, byte[] operationState,
            long encryptionKey, long authenticationKey) {
        return NC.SetOperationState(NATIVE, session, operationState, encryptionKey, authenticationKey);
    }

    /**
     * Logs a user into a token.
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link Ci#Login(long, long, byte[])} instead
     */
    @Deprecated
    public static long Login(long session, long userType, byte[] pin) {
        return NC.Login(NATIVE, session, userType, pin);
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_Logout(long)
     * @deprecated use {@link Ci#Logout(long)} instead
     */
    @Deprecated
    public static long Logout(long session) {
        return NC.Logout(NATIVE, session);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     * @deprecated use {@link Ci#CreateObject(long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static long CreateObject(long session, CKA[] templ, LongRef object) {
        return NC.CreateObject(NATIVE, session, templ, object);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @return {@link CKR} return code
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     * @deprecated use {@link Ci#CopyObject(long, long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static long CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        return NC.CopyObject(NATIVE, session, object, templ, newObject);
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_DestroyObject(long, long)
     * @deprecated use {@link Ci#DestroyObject(long, long)} instead
     */
    @Deprecated
    public static long DestroyObject(long session, long object) {
        return NC.DestroyObject(NATIVE, session, object);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     * @deprecated use {@link Ci#GetObjectSize(long, long, LongRef)} instead
     */
    @Deprecated
    public static long GetObjectSize(long session, long object, LongRef size) {
        return NC.GetObjectSize(NATIVE, session, object, size);
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     * @deprecated use {@link Ci#GetAttributeValue(long, long, CKA[])} instead
     */
    @Deprecated
    public static long GetAttributeValue(long session, long object, CKA[] templ) {
        return NC.GetAttributeValue(NATIVE, session, object, templ);
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     * @deprecated use {@link Ci#SetAttributeValue(long, long, CKA[])} instead
     */
    @Deprecated
    public static long SetAttributeValue(long session, long object, CKA[] templ) {
        return NC.SetAttributeValue(NATIVE, session, object, templ);
    }

    /**
     * Initialises a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     * @deprecated use {@link Ci#FindObjectsInit(long, CKA[])} instead
     */
    @Deprecated
    public static long FindObjectsInit(long session, CKA[] templ) {
        return NC.FindObjectsInit(NATIVE, session, templ);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     * @deprecated use {@link Ci#FindObjects(long, long[], LongRef)} instead
     */
    @Deprecated
    public static long FindObjects(long session, long[] found, LongRef objectCount) {
        return NC.FindObjects(NATIVE, session, found, objectCount);
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsFinal(long)
     * @deprecated use {@link Ci#FindObjectsFinal(long)} instead
     */
    @Deprecated
    public static long FindObjectsFinal(long session) {
        return NC.FindObjectsFinal(NATIVE, session);
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     * @deprecated use {@link Ci#EncryptInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long EncryptInit(long session, CKM mechanism, long key) {
        return NC.EncryptInit(NATIVE, session, mechanism, key);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#Encrypt(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        return NC.Encrypt(NATIVE, session, data, encryptedData, encryptedDataLen);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#EncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return NC.EncryptUpdate(NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     * @deprecated use {@link Ci#EncryptFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        return NC.EncryptFinal(NATIVE, session, lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     * Intialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     * @deprecated use {@link Ci#DecryptInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long DecryptInit(long session, CKM mechanism, long key) {
        return NC.DecryptInit(NATIVE, session, mechanism, key);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#Decrypt(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        return NC.Decrypt(NATIVE, session, encryptedData, data, dataLen);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#DecryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        return NC.DecryptUpdate(NATIVE, session, encryptedPart, data, dataLen);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     * @deprecated use {@link Ci#DecryptFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        return NC.DecryptFinal(NATIVE, session, lastPart, lastPartLen);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestInit(long, CKM)
     * @deprecated use {@link Ci#DigestInit(long, CKM)} instead
     */
    @Deprecated
    public static long DigestInit(long session, CKM mechanism) {
        return NC.DigestInit(NATIVE, session, mechanism);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @return {@link CKR} return code
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#Digest(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        return NC.Digest(NATIVE, session, data, digest, digestLen);
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     * @deprecated use {@link Ci#DigestUpdate(long, byte[])} instead
     */
    @Deprecated
    public static long DigestUpdate(long session, byte[] part) {
        return NC.DigestUpdate(NATIVE, session, part);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestKey(long, long)
     * @deprecated use {@link Ci#DigestKey(long, long)} instead
     */
    @Deprecated
    public static long DigestKey(long session, long key) {
        return NC.DigestKey(NATIVE, session, key);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     * @deprecated use {@link Ci#DigestFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long DigestFinal(long session, byte[] digest, LongRef digestLen) {
        return NC.DigestFinal(NATIVE, session, digest, digestLen);
    }

    /**
     * Initialises a signature (private key encryption) operation, where
     * the signature is (will be) an appendix to the data, and plaintext
     * cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignInit(long, CKM, long)
     * @deprecated use {@link Ci#SignInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long SignInit(long session, CKM mechanism, long key) {
        return NC.SignInit(NATIVE, session, mechanism, key);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#Sign(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        return NC.Sign(NATIVE, session, data, signature, signatureLen);
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     * @deprecated use {@link Ci#SignUpdate(long, byte[])} instead
     */
    @Deprecated
    public static long SignUpdate(long session, byte[] part) {
        return NC.SignUpdate(NATIVE, session, part);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     * @deprecated use {@link Ci#SignFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long SignFinal(long session, byte[] signature, LongRef signatureLen) {
        return NC.SignFinal(NATIVE, session, signature, signatureLen);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     * @deprecated use {@link Ci#SignRecoverInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long SignRecoverInit(long session, CKM mechanism, long key) {
        return NC.SignRecoverInit(NATIVE, session, mechanism, key);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#SignRecover(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        return NC.SignRecover(NATIVE, session, data, signature, signatureLen);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     * @deprecated use {@link Ci#VerifyInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long VerifyInit(long session, CKM mechanism, long key) {
        return NC.VerifyInit(NATIVE, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @return {@link CKR} return code
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     * @deprecated use {@link Ci#Verify(long, byte[], byte[])} instead
     */
    @Deprecated
    public static long Verify(long session, byte[] data, byte[] signature) {
        return NC.Verify(NATIVE, session, data, signature);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     * @deprecated use {@link Ci#VerifyUpdate(long, byte[])} instead
     */
    @Deprecated
    public static long VerifyUpdate(long session, byte[] part) {
        return NC.VerifyUpdate(NATIVE, session, part);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     * @deprecated use {@link Ci#VerifyFinal(long, byte[])} instead
     */
    @Deprecated
    public static long VerifyFinal(long session, byte[] signature) {
        return NC.VerifyFinal(NATIVE, session, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     * @deprecated use {@link Ci#VerifyRecoverInit(long, CKM, long)} instead
     */
    @Deprecated
    public static long VerifyRecoverInit(long session, CKM mechanism, long key) {
        return NC.VerifyRecoverInit(NATIVE, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#VerifyRecover(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        return NC.VerifyRecover(NATIVE, session, signature, data, dataLen);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#DigestEncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return NC.DigestEncryptUpdate(NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#DecryptDigestUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        return NC.DecryptDigestUpdate(NATIVE, session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#SignEncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        return NC.SignEncryptUpdate(NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link Ci#DecryptVerifyUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static long DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        return NC.DecryptVerifyUpdate(NATIVE, session, encryptedPart, part, partLen);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     * @deprecated use {@link Ci#GenerateKey(long, CKM, CKA[], LongRef)} instead
     */
    @Deprecated
    public static long GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        return NC.GenerateKey(NATIVE, session, mechanism, templ, key);
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
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, CKA[], long, CKA[], long, LongRef, LongRef)
     * @deprecated use {@link Ci#GenerateKeyPair(long, CKM, CKA[], CKA[], LongRef, LongRef)} instead
     */
    @Deprecated
    public static long GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate,
                                       CKA[] privateKeyTemplate, LongRef publicKey, LongRef privateKey) {
        return NC.GenerateKeyPair(NATIVE, session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
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
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     * @deprecated use {@link Ci#WrapKey(long, CKM, long, long, byte[], LongRef)} instead
     */
    @Deprecated
    public static long WrapKey(long session, CKM mechanism, long wrappingKey, long key,
                               byte[] wrappedKey, LongRef wrappedKeyLen) {

        return NC.WrapKey(NATIVE, session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
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
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     * @deprecated use {@link Ci#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)} instead
     */
    @Deprecated
    public static long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey,
            CKA[] templ, LongRef key) {
        return NC.UnwrapKey(NATIVE, session, mechanism, unwrappingKey, wrappedKey, templ, key);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @param key ges new handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     * @deprecated use {@link Ci#DeriveKey(long, CKM, long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static long DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        return NC.DeriveKey(NATIVE, session, mechanism, baseKey, templ, key);
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @return {@link CKR} return code
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     * @deprecated use {@link Ci#SeedRandom(long, byte[])} instead
     */
    @Deprecated
    public static long SeedRandom(long session, byte[] seed) {
        return NC.SeedRandom(NATIVE, session, seed);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     * @deprecated use {@link Ci#GenerateRandom(long, byte[])} instead
     */
    @Deprecated
    public static long GenerateRandom(long session, byte[] randomData) {
        return NC.GenerateRandom(NATIVE, session, randomData);
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetFunctionStatus(long)
     * @deprecated use {@link Ci#GetFunctionStatus(long)} instead
     */
    @Deprecated
    public static long GetFunctionStatus(long session) {
        return NC.GetFunctionStatus(NATIVE, session);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CancelFunction(long)
     * @deprecated use {@link Ci#CancelFunction(long)} instead
     */
    @Deprecated
    public static long CancelFunction(long session) {
        return NC.CancelFunction(NATIVE, session);
    }

    /**
     * Helper method.  Adds all public static final long fields in c to map, mapping field value to name.
     * @param c class
     * @return map of field value:name
     * @deprecated use {@link NC#createL2SMap(Class)} instead
     */
    @Deprecated
    public static Map<Long, String> createL2SMap(Class<?> c) {
        return NC.createL2SMap(c);
    }

    /**
     * Helper method, Maps l to constant name, or value 'unknown %s constant 0x08x' % (ckx, l)'.
     * @param map L2S map
     * @param ckx prefix of constant type, e.g. 'CKA'
     * @param l constant value
     * @return constant name, or value 'unknown %s constant 0x08x' % (ckx, l)'.
     * @deprecated use {@link NC#l2s(Map, String, long)} instead
     */
    @Deprecated
    public static String l2s(Map<Long, String> map, String ckx, long l) {
        return NC.l2s(map, ckx, l);
    }

    /**
     * Helper method.  String format of flags.
     * @param l2s l2s map
     * @param flags flags
     * @return string format of flags
     * @deprecated use {@link NC#f2s(Map, long)} instead
     */
    @Deprecated
    public static String f2s(Map<Long, String> l2s, long flags) {
        return NC.f2s(l2s, flags);
    }
}
