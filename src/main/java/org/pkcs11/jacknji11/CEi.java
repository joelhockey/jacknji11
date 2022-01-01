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

import org.pkcs11.jacknji11.jna.JNA;

/**
 * This is the preferred java interface for calling cryptoki functions.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link NativeProvider} provides the lowest level
 * direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link C} provides the exact same functions
 * as {@link NativeProvider} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'C.'</code> when you call the
 * static methods of this class looks similar.  In addition to calling
 * the native methods, {@link C} provides logging
 * through apache commons logging.  You can use this if you require fine-grain
 * control over something such as checking
 * {@link CKR} return codes.
 * <li>{@link CEi} (<b>C</b>ryptoki
 * with <b>E</b>xceptions) provides the most user-friendly interface
 * and is the preferred interface to use.  It calls
 * related function(s) in {@link C},
 * and converts any non-zero return values into a
 * {@link CKRException}.  It automatically resizes
 * arrays and other helpful things.
 * </ol>
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CEi {

    private final NativeProvider nativeProvider;

    public CEi(NativeProvider nativeProvider) {
        this.nativeProvider = nativeProvider;
    }

    public CEi() {
        this(new JNA(NC.getLibraryName()));
    }

    /**
     * Initialize cryptoki.
     * @see NC#Initialize(NativeProvider)
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     */
    public void Initialize() {
        NCE.Initialize(nativeProvider);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see NC#Finalize(NativeProvider)
     * @see NativeProvider#C_Finalize(NativePointer)
     */
    public void Finalize() {
        NCE.Finalize(nativeProvider);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see NC#GetInfo(NativeProvider, CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public void GetInfo(CK_INFO info) {
        NCE.GetInfo(nativeProvider, info);
    }

    /**
     * Returns general information about Cryptoki.
     * @return info
     * @see NC#GetInfo(NativeProvider, CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public CK_INFO GetInfo() {
        return NCE.GetInfo(nativeProvider);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see NC#GetSlotList(NativeProvider, boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public void GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        NCE.GetSlotList(nativeProvider, tokenPresent, slotList, count);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see NC#GetSlotList(NativeProvider, boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public long[] GetSlotList(boolean tokenPresent) {
        return NCE.GetSlotList(nativeProvider, tokenPresent);
    }

    /**
     * Return first slot with given label else throw CKRException.
     * @param label label of slot to find
     * @return slot id or CKRException if no slot found
     * @see NC#GetSlotList(NativeProvider, boolean, long[], LongRef)
     * @see NC#GetTokenInfo(NativeProvider, long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public long GetSlot(String label) {
        return NCE.GetSlot(nativeProvider, label);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @see NC#GetSlotInfo(NativeProvider, long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public void GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        NCE.GetSlotInfo(nativeProvider, slotID, info);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see NC#GetSlotInfo(NativeProvider, long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public CK_SLOT_INFO GetSlotInfo(long slotID) {
        return NCE.GetSlotInfo(nativeProvider, slotID);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see NC#GetTokenInfo(NativeProvider, long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public void GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        NCE.GetTokenInfo(nativeProvider, slotID, info);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see NC#GetTokenInfo(NativeProvider, long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public CK_TOKEN_INFO GetTokenInfo(long slotID) {
        return NCE.GetTokenInfo(nativeProvider, slotID);
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param pReserved reserved.  Should be null
     * @see NC#WaitForSlotEvent(NativeProvider, long, LongRef, NativePointer)
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    public void WaitForSlotEvent(long flags, LongRef slot, NativePointer pReserved) {
        NCE.WaitForSlotEvent(nativeProvider, flags, slot, pReserved);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see NC#GetMechanismList(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public void GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        NCE.GetMechanismList(nativeProvider, slotID, mechanismList, count);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see NC#GetMechanismList(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public long[] GetMechanismList(long slotID) {
        return NCE.GetMechanismList(nativeProvider, slotID);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see NC#GetMechanismInfo(NativeProvider, long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public void GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        NCE.GetMechanismInfo(nativeProvider, slotID, type, info);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see NC#GetMechanismInfo(NativeProvider, long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public CK_MECHANISM_INFO GetMechanismInfo(long slotID, long type) {
        return NCE.GetMechanismInfo(nativeProvider, slotID, type);
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's initial PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @see NC#InitToken(NativeProvider, long, byte[], byte[])
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     */
    public void InitToken(long slotID, byte[] pin, byte[] label) {
        NCE.InitToken(nativeProvider, slotID, pin, label);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see NC#InitPIN(NativeProvider, long, byte[])
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    public void InitPIN(long session, byte[] pin) {
        NCE.InitPIN(nativeProvider, session, pin);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see NC#SetPIN(NativeProvider, long, byte[], byte[])
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    public void SetPIN(long session, byte[] oldPin, byte[] newPin) {
        NCE.SetPIN(nativeProvider, session, oldPin, newPin);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param session gets session handle
     * @see NC#OpenSession(NativeProvider, long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public void OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        NCE.OpenSession(nativeProvider, slotID, flags, application, notify, session);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @return session handle
     * @see NC#OpenSession(NativeProvider, long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        return NCE.OpenSession(nativeProvider, slotID, flags, application, notify);
    }

    /**
     * Opens a session between an application and a token using {@link CK_SESSION_INFO#CKF_RW_SESSION and CK_SESSION_INFO#CKF_SERIAL_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see NC#OpenSession(NativeProvider, long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public long OpenSession(long slotID) {
        return NCE.OpenSession(nativeProvider, slotID);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see NC#CloseSession(NativeProvider, long)
     * @see NativeProvider#C_CloseSession(long)
     */
    public void CloseSession(long session) {
        NCE.CloseSession(nativeProvider, session);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see NC#CloseAllSessions(NativeProvider, long)
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public void CloseAllSessions(long slotID) {
        NCE.CloseAllSessions(nativeProvider, slotID);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see NC#GetSessionInfo(NativeProvider, long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public void GetSessionInfo(long session, CK_SESSION_INFO info) {
        NCE.GetSessionInfo(nativeProvider, session, info);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see NC#GetSessionInfo(NativeProvider, long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public CK_SESSION_INFO GetSessionInfo(long session) {
        return NCE.GetSessionInfo(nativeProvider, session);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see NC#GetOperationState(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public void GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        NCE.GetOperationState(nativeProvider, session, operationState, operationStateLen);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see NC#GetOperationState(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public byte[] GetOperationState(long session) {
        return NCE.GetOperationState(nativeProvider, session);
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @see NC#SetOperationState(NativeProvider, long, byte[], long, long)
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     */
    public void SetOperationState(long session, byte[] operationState, long encryptionKey, long authenticationKey) {
        NCE.SetOperationState(nativeProvider, session, operationState, encryptionKey, authenticationKey);
    }

    /**
     * Logs a user into a token.  Ignores CKR=0x00000100: USER_ALREADY_LOGGED_IN
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void Login(long session, long userType, byte[] pin) {
        NCE.Login(nativeProvider, session, userType, pin);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginUser(long session, byte[] pin) {
        NCE.LoginUser(nativeProvider, session, pin);
    }

    /**
     * Los a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN encoded in a single byte encoding format such as ISO8859-1
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginUser(long session, String pin) {
        NCE.LoginUser(nativeProvider, session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginSO(long session, byte[] pin) {
        NCE.LoginSO(nativeProvider, session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN encoded in a single byte encoding format such as ISO8859-1
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginSO(long session, String pin) {
        NCE.LoginSO(nativeProvider, session, pin);
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see NC#Logout(NativeProvider, long)
     * @see NativeProvider#C_Logout(long)
     */
    public void Logout(long session) {
        NCE.Logout(nativeProvider, session);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see NC#CreateObject(NativeProvider, long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public void CreateObject(long session, CKA[] templ, LongRef object) {
        NCE.CreateObject(nativeProvider, session, templ, object);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see NC#CreateObject(NativeProvider, long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public long CreateObject(long session, CKA... templ) {
        return NCE.CreateObject(nativeProvider, session, templ);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @see NC#CopyObject(NativeProvider, long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     */
    public void CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        NCE.CopyObject(nativeProvider, session, object, templ, newObject);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @return new object handle
     * @see NC#CopyObject(NativeProvider, long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     */
    public long CopyObject(long session, long object, CKA... templ) {
        return NCE.CopyObject(nativeProvider, session, object, templ);
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see NC#DestroyObject(NativeProvider, long, long)
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    public void DestroyObject(long session, long object) {
        NCE.DestroyObject(nativeProvider, session, object);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see NC#GetObjectSize(NativeProvider, long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public void GetObjectSize(long session, long object, LongRef size) {
        NCE.GetObjectSize(nativeProvider, session, object, size);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see NC#GetObjectSize(NativeProvider, long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public long GetObjectSize(long session, long object) {
        return NCE.GetObjectSize(nativeProvider, session, object);
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @see NC#GetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public void GetAttributeValue(long session, long object, CKA... templ) {
        NCE.GetAttributeValue(nativeProvider, session, object, templ);
    }

    /**
     * Obtains the value of one attributes, or returns CKA with null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see NC#GetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public CKA GetAttributeValue(long session, long object, long cka) {
        return NCE.GetAttributeValue(nativeProvider, session, object, cka);
    }

    /**
     * Obtains the value of one or more object attributes. Sets value to null
     * if object does not include attribute.
     * @param session the session's handle
     * @param object the objects's handle
     * @param types {@link CKA} attribute types to get
     * @return attribute values
     * @see NC#GetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public CKA[] GetAttributeValue(long session, long object, long... types) {
        return NCE.GetAttributeValue(nativeProvider, session, object, types);
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @see NC#SetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    public void SetAttributeValue(long session, long object, CKA... templ) {
        NCE.SetAttributeValue(nativeProvider, session, object, templ);
    }

    /**
     * Initialises a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see NC#FindObjectsInit(NativeProvider, long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public void FindObjectsInit(long session, CKA... templ) {
        NCE.FindObjectsInit(nativeProvider, session, templ);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @see NC#FindObjects(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     */
    public void FindObjects(long session, long[] found, LongRef objectCount) {
        NCE.FindObjects(nativeProvider, session, found, objectCount);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param maxObjects maximum objects to return
     * @return list of object handles
     * @see NC#FindObjects(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     */
    public long[] FindObjects(long session, int maxObjects) {
        return NCE.FindObjects(nativeProvider, session, maxObjects);
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @see NC#FindObjectsFinal(NativeProvider, long)
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public void FindObjectsFinal(long session) {
        NCE.FindObjectsFinal(nativeProvider, session);
    }

    /**
     * Single-part search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see NC#FindObjectsInit(NativeProvider, long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public long[] FindObjects(long session, CKA... templ) {
        return NCE.FindObjects(nativeProvider, session, templ);
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see NC#EncryptInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    public void EncryptInit(long session, CKM mechanism, long key) {
        NCE.EncryptInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @see NC#Encrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public void Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        NCE.Encrypt(nativeProvider, session, data, encryptedData, encryptedDataLen);
    }

    /**
     * Encrypts single-part data with 2 calls.  First call determines
     * size of result which may include padding, second call does encrypt.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see NC#Encrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] EncryptPad(long session, byte[] data) {
        return NCE.EncryptPad(nativeProvider, session, data);
    }

    /**
     * Encrypts single-part data with single call assuming result
     * has no padding and is same size as input.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see NC#Encrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] Encrypt(long session, byte[] data) {
        return NCE.Encrypt(nativeProvider, session, data);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @see NC#EncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public void EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.EncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#EncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] EncryptUpdate(long session, byte[] part) {
        return NCE.EncryptUpdate(nativeProvider, session, part);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see NC#EncryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public void EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        NCE.EncryptFinal(nativeProvider, session, lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see NC#EncryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public byte[] EncryptFinal(long session) {
        return NCE.EncryptFinal(nativeProvider, session);
    }

    /**
     * Encrypts single-part data with 2 calls.  First call determines
     * size of result which may include padding, second call does encrypt.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @param data the plaintext data
     * @return encrypted data
     * @see NC#Encrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] EncryptPad(long session, CKM mechanism, long key, byte[] data) {
        return NCE.EncryptPad(nativeProvider, session, mechanism, key, data);
    }

    /**
     * Encrypts single-part data with single call assuming result
     * has no padding and is same size as input.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @param data the plaintext data
     * @return encrypted data
     * @see NC#Encrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] Encrypt(long session, CKM mechanism, long key, byte[] data) {
        return NCE.Encrypt(nativeProvider, session, mechanism, key, data);
    }

    /**
     * Initialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see NC#DecryptInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    public void DecryptInit(long session, CKM mechanism, long key) {
        NCE.DecryptInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public void Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        NCE.Decrypt(nativeProvider, session, encryptedData, data, dataLen);
    }

    /**
     * Decrypts encrypted data in a single-part with 2 calls.  First call determines
     * size of result which may have padding removed, second call does decrypt.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptPad(long session, byte[] encryptedData) {
        return NCE.DecryptPad(nativeProvider, session, encryptedData);
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] Decrypt(long session, byte[] encryptedData) {
        return NCE.Decrypt(nativeProvider, session, encryptedData);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @see NC#DecryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public void DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        NCE.DecryptUpdate(nativeProvider, session, encryptedPart, data, dataLen);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see NC#DecryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptUpdate(nativeProvider, session, encryptedPart);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see NC#DecryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public void DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        NCE.DecryptFinal(nativeProvider, session, lastPart, lastPartLen);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see NC#DecryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public byte[] DecryptFinal(long session) {
        return NCE.DecryptFinal(nativeProvider, session);
    }

    /**
     * Decrypts encrypted data in a single-part with 2 calls.  First call determines
     * size of result which may have padding removed, second call does decrypt.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @param encryptedData cipertext
     * @return plaintext
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptPad(long session, CKM mechanism, long key, byte[] encryptedData) {
        return NCE.DecryptPad(nativeProvider, session, mechanism, key, encryptedData);
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @param encryptedData cipertext
     * @return plaintext
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] Decrypt(long session, CKM mechanism, long key, byte[] encryptedData) {
        return NCE.Decrypt(nativeProvider, session, mechanism, key, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see NC#DigestInit(NativeProvider, long, CKM)
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    public void DigestInit(long session, CKM mechanism) {
        NCE.DigestInit(nativeProvider, session, mechanism);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @see NC#Digest(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public void Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        NCE.Digest(nativeProvider, session, data, digest, digestLen);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see NC#Digest(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public byte[] Digest(long session, byte[] data) {
        return NCE.Digest(nativeProvider, session, data);
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see NC#DigestUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public void DigestUpdate(long session, byte[] part) {
        NCE.DigestUpdate(nativeProvider, session, part);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see NC#DigestKey(NativeProvider, long, long)
     * @see NativeProvider#C_DigestKey(long, long)
     */
    public void DigestKey(long session, long key) {
        NCE.DigestKey(nativeProvider, session, key);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see NC#DigestFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public void DigestFinal(long session, byte[] digest, LongRef digestLen) {
        NCE.DigestFinal(nativeProvider, session, digest, digestLen);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see NC#DigestFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public byte[] DigestFinal(long session) {
        return NCE.DigestFinal(nativeProvider, session);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @param data data to be digested
     * @return digest
     * @see NC#Digest(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public byte[] Digest(long session, CKM mechanism, byte[] data) {
        return NCE.Digest(nativeProvider, session, mechanism, data);
    }

    /**
     * Initialises a signature (private key encryption) operation, where
     * the signature is (will be) an appendix to the data, and plaintext
     * cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @see NC#SignInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_SignInit(long, CKM, long)
     */
    public void SignInit(long session, CKM mechanism, long key) {
        NCE.SignInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see NC#Sign(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public void Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        NCE.Sign(nativeProvider, session, data, signature, signatureLen);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see NC#Sign(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public byte[] Sign(long session, byte[] data) {
        return NCE.Sign(nativeProvider, session, data);
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @see NC#SignUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     */
    public void SignUpdate(long session, byte[] part) {
        NCE.SignUpdate(nativeProvider, session, part);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see NC#SignFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public void SignFinal(long session, byte[] signature, LongRef signatureLen) {
        NCE.SignFinal(nativeProvider, session, signature, signatureLen);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see NC#SignFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public byte[] SignFinal(long session) {
        return NCE.SignFinal(nativeProvider, session);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @param data the data to sign
     * @return signature
     * @see NC#Sign(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public byte[] Sign(long session, CKM mechanism, long key, byte[] data) {
        return NCE.Sign(nativeProvider, session, mechanism, key, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see NC#SignRecoverInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    public void SignRecoverInit(long session, CKM mechanism, long key) {
        NCE.SignRecoverInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see NC#SignRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public void SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        NCE.SignRecover(nativeProvider, session, data, signature, signatureLen);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see NC#SignRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] SignRecover(long session, byte[] data) {
        return NCE.SignRecover(nativeProvider, session, data);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @param data the data to sign
     * @return signature
     * @see NC#SignRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] SignRecover(long session, CKM mechanism, long key, byte[] data) {
        return NCE.SignRecover(nativeProvider, session, mechanism, key, data);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see NC#VerifyInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     */
    public void VerifyInit(long session, CKM mechanism, long key) {
        NCE.VerifyInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @see NC#Verify(NativeProvider, long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public void Verify(long session, byte[] data, byte[] signature) {
        NCE.Verify(nativeProvider, session, data, signature);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see NC#VerifyUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    public void VerifyUpdate(long session, byte[] part) {
        NCE.VerifyUpdate(nativeProvider, session, part);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see NC#VerifyFinal(NativeProvider, long, byte[])
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    public void VerifyFinal(long session, byte[] signature) {
        NCE.VerifyFinal(nativeProvider, session, signature);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @param data signed data
     * @param signature signature
     * @see NC#Verify(NativeProvider, long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public void Verify(long session, CKM mechanism, long key, byte[] data, byte[] signature) {
        NCE.Verify(nativeProvider, session, mechanism, key, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see NC#VerifyRecoverInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    public void VerifyRecoverInit(long session, CKM mechanism, long key) {
        NCE.VerifyRecoverInit(nativeProvider, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @see NC#VerifyRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public void VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        NCE.VerifyRecover(nativeProvider, session, signature, data, dataLen);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see NC#VerifyRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] VerifyRecover(long session, byte[] signature) {
        return NCE.VerifyRecover(nativeProvider, session, signature);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @param signature signature to verify
     * @return data
     * @see NC#VerifyRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] VerifyRecover(long session, CKM mechanism, long key, byte[] signature) {
        return NCE.VerifyRecover(nativeProvider, session, mechanism, key, signature);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @see NC#DigestEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public void DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.DigestEncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#DigestEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DigestEncryptUpdate(long session, byte[] part) {
        return NCE.DigestEncryptUpdate(nativeProvider, session, part);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @see NC#DigestUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public void DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        NCE.DecryptDigestUpdate(nativeProvider, session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see NC#DecryptDigestUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptDigestUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptDigestUpdate(nativeProvider, session, encryptedPart);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @see NC#SignEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public void SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.SignEncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#SignEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] SignEncryptUpdate(long session, byte[] part) {
        return NCE.SignEncryptUpdate(nativeProvider, session, part);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @see NC#DecryptVerifyUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public void DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        NCE.DecryptVerifyUpdate(nativeProvider, session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see NC#DecryptVerifyUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptVerifyUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptVerifyUpdate(nativeProvider, session, encryptedPart);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @see NC#GenerateKey(NativeProvider, long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     */
    public void GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        NCE.GenerateKey(nativeProvider, session, mechanism, templ, key);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @return key handle
     * @see NC#GenerateKey(NativeProvider, long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     */
    public long GenerateKey(long session, CKM mechanism, CKA... templ) {
        return NCE.GenerateKey(nativeProvider, session, mechanism, templ);
    }

    /**
     * Generates a public-key / private-key pair, create new key objects.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param publicKeyTemplate template for the new public key
     * @param privateKeyTemplate template for the new private key
     * @param publicKey gets handle of new public key
     * @param privateKey gets handle of new private key
     * @see NC#GenerateKeyPair(NativeProvider, long, CKM, CKA[], CKA[], LongRef, LongRef)
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, CKA[], long, CKA[], long, LongRef, LongRef)
     */
    public void GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate,
                                       LongRef publicKey, LongRef privateKey) {
        NCE.GenerateKeyPair(nativeProvider, session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
    }

    /**
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @param wrappedKey gets wrapped key
     * @param wrappedKeyLen gets wrapped key length
     * @see NC#WrapKey(NativeProvider, long, CKM, long, long, byte[], LongRef)
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public void WrapKey(long session, CKM mechanism, long wrappingKey, long key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        NCE.WrapKey(nativeProvider, session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
    }

    /**
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @return wrapped key
     * @see NC#WrapKey(NativeProvider, long, CKM, long, long, byte[], LongRef)
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public byte[] WrapKey(long session, CKM mechanism, long wrappingKey, long key) {
        return NCE.WrapKey(nativeProvider, session, mechanism, wrappingKey, key);
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @param key gets new handle
     * @see NC#UnwrapKey(NativeProvider, long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public void UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        NCE.UnwrapKey(nativeProvider, session, mechanism, unwrappingKey, wrappedKey, templ, key);
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @return key handle
     * @see NC#UnwrapKey(NativeProvider, long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        return NCE.UnwrapKey(nativeProvider, session, mechanism, unwrappingKey, wrappedKey, templ);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @param key ges new handle
     * @see NC#DeriveKey(NativeProvider, long, CKM, long, CKA[], LongRef)
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     */
    public void DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        NCE.DeriveKey(nativeProvider, session, mechanism, baseKey, templ, key);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @return new handle
     * @see NC#DeriveKey(NativeProvider, long, CKM, long, CKA[], LongRef)
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     */
    public long DeriveKey(long session, CKM mechanism, long baseKey, CKA... templ) {
        return NCE.DeriveKey(nativeProvider, session, mechanism, baseKey, templ);
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see NC#SeedRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    public void SeedRandom(long session, byte[] seed) {
        NCE.SeedRandom(nativeProvider, session, seed);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see NC#GenerateRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public void GenerateRandom(long session, byte[] randomData) {
        NCE.GenerateRandom(nativeProvider, session, randomData);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see NC#GenerateRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public byte[] GenerateRandom(long session, int randomLen) {
        return NCE.GenerateRandom(nativeProvider, session, randomLen);
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see NC#GetFunctionStatus(NativeProvider, long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public void GetFunctionStatus(long session) {
        NCE.GetFunctionStatus(nativeProvider, session);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see NC#GetFunctionStatus(NativeProvider, long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public void CancelFunction(long session) {
        NCE.CancelFunction(nativeProvider, session);
    }
}
