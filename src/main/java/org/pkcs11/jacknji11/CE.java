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

/**
 * Historical preferred interface for calling cryptoki functions.  This class is
 * kept for backwards compatibility, and you should prefer to use
 * the non-static {@link org.pkcs11.jacknji11.CryptokiE}.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions (plus 2 for
 * backwards compatibility).
 * <ol>
 * <li>{@link org.pkcs11.jacknji11.NativeProvider} provides the lowest level
 * direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link org.pkcs11.jacknji11.Cryptoki} provides the exact same functions
 * as {@link org.pkcs11.jacknji11.NativeProvider} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'c.'</code> when you call the
 * methods of this class looks similar (assuming the instance is named
 * <code>'c'</code>).  In addition to calling
 * the native methods, {@link org.pkcs11.jacknji11.Cryptoki} provides logging
 * through apache commons logging.  You can use this if you require fine-grain
 * control over something such as checking
 * {@link org.pkcs11.jacknji11.CKR} return codes.
 * <li>{@link org.pkcs11.jacknji11.CryptokiE} (<b>Cryptoki</b>
 * with <b>E</b>xceptions) provides the most user-friendly interface
 * and is the preferred interface to use.  It calls
 * related function(s) in {@link org.pkcs11.jacknji11.Cryptoki},
 * and converts any non-zero return values into a
 * {@link org.pkcs11.jacknji11.CKRException}.  It automatically resizes
 * arrays and other helpful things.
 * <li>{@link org.pkcs11.jacknji11.C} and {@link org.pkcs11.jacknji11.CE} are
 * the static predecessors to {@link org.pkcs11.jacknji11.Cryptoki} and
 * {@link org.pkcs11.jacknji11.CryptokiE}.  They are kept mostly for backwards
 * compatibility.
 * </ol>
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CE {

    static CryptokiE CRYPTOKIE;

    /**
     * Initialize cryptoki.
     * @see C#Initialize()
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     */
    public static void Initialize() {
        if (CRYPTOKIE == null) {
            C.initCryptoki();
            CRYPTOKIE = new CryptokiE(new Cryptoki(C.NATIVE));
        }
        CRYPTOKIE.Initialize();
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see C#Finalize()
     * @see NativeProvider#C_Finalize(NativePointer)
     */
    public static void Finalize() {
        CRYPTOKIE.Finalize();
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public static void GetInfo(CK_INFO info) {
        CRYPTOKIE.GetInfo(info);
    }

    /**
     * Returns general information about Cryptoki.
     * @return info
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public static CK_INFO GetInfo() {
        return CRYPTOKIE.GetInfo();
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public static void GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        CRYPTOKIE.GetSlotList(tokenPresent, slotList, count);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public static long[] GetSlotList(boolean tokenPresent) {
        return CRYPTOKIE.GetSlotList(tokenPresent);
    }

    /**
     * Return first slot with given label else throw CKRException.
     * @param label label of slot to find
     * @return slot id or CKRException if no slot found
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public static long GetSlot(String label) {
        return CRYPTOKIE.GetSlot(label);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public static void GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        CRYPTOKIE.GetSlotInfo(slotID, info);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public static CK_SLOT_INFO GetSlotInfo(long slotID) {
        return CRYPTOKIE.GetSlotInfo(slotID);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public static void GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        CRYPTOKIE.GetTokenInfo(slotID, info);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public static CK_TOKEN_INFO GetTokenInfo(long slotID) {
        return CRYPTOKIE.GetTokenInfo(slotID);
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param pReserved reserved.  Should be null
     * @see C#WaitForSlotEvent(long, LongRef, NativePointer)
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    public static void WaitForSlotEvent(long flags, LongRef slot, NativePointer pReserved) {
        CRYPTOKIE.WaitForSlotEvent(flags, slot, pReserved);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public static void GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        CRYPTOKIE.GetMechanismList(slotID, mechanismList, count);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public static long[] GetMechanismList(long slotID) {
        return CRYPTOKIE.GetMechanismList(slotID);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public static void GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        CRYPTOKIE.GetMechanismInfo(slotID, type, info);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public static CK_MECHANISM_INFO GetMechanismInfo(long slotID, long type) {
        return CRYPTOKIE.GetMechanismInfo(slotID, type);
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's initial PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @see C#InitToken(long, byte[], byte[])
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     */
    public static void InitToken(long slotID, byte[] pin, byte[] label) {
        CRYPTOKIE.InitToken(slotID, pin, label);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#InitPIN(long, byte[])
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    public static void InitPIN(long session, byte[] pin) {
        CRYPTOKIE.InitPIN(session, pin);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see C#SetPIN(long, byte[], byte[])
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    public static void SetPIN(long session, byte[] oldPin, byte[] newPin) {
        CRYPTOKIE.SetPIN(session, oldPin, newPin);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param session gets session handle
     * @see C#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public static void OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        CRYPTOKIE.OpenSession(slotID, flags, application, notify, session);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @return session handle
     * @see C#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public static long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        return CRYPTOKIE.OpenSession(slotID, flags, application, notify);
    }

    /**
     * Opens a session between an application and a token using {@link CK_SESSION_INFO#CKF_RW_SESSION and CK_SESSION_INFO#CKF_SERIAL_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see C#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public static long OpenSession(long slotID) {
        return CRYPTOKIE.OpenSession(slotID);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see C#CloseSession(long)
     * @see NativeProvider#C_CloseSession(long)
     */
    public static void CloseSession(long session) {
        CRYPTOKIE.CloseSession(session);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see C#CloseAllSessions(long)
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public static void CloseAllSessions(long slotID) {
        CRYPTOKIE.CloseAllSessions(slotID);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public static void GetSessionInfo(long session, CK_SESSION_INFO info) {
        CRYPTOKIE.GetSessionInfo(session, info);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public static CK_SESSION_INFO GetSessionInfo(long session) {
        return CRYPTOKIE.GetSessionInfo(session);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public static void GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        CRYPTOKIE.GetOperationState(session, operationState, operationStateLen);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public static byte[] GetOperationState(long session) {
        return CRYPTOKIE.GetOperationState(session);
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @see C#SetOperationState(long, byte[], long, long)
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     */
    public static void SetOperationState(long session, byte[] operationState, long encryptionKey, long authenticationKey) {
        CRYPTOKIE.SetOperationState(session, operationState, encryptionKey, authenticationKey);
    }

    /**
     * Logs a user into a token.  Ignores CKR=0x00000100: USER_ALREADY_LOGGED_IN
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static void Login(long session, long userType, byte[] pin) {
        CRYPTOKIE.Login(session, userType, pin);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static void LoginUser(long session, byte[] pin) {
        CRYPTOKIE.LoginUser(session, pin);
    }

    /**
     * Los a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static void LoginUser(long session, String pin) {
        CRYPTOKIE.LoginUser(session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static void LoginSO(long session, byte[] pin) {
        CRYPTOKIE.LoginSO(session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static void LoginSO(long session, String pin) {
        CRYPTOKIE.LoginSO(session, pin);
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see C#Logout(long)
     * @see NativeProvider#C_Logout(long)
     */
    public static void Logout(long session) {
        CRYPTOKIE.Logout(session);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public static void CreateObject(long session, CKA[] templ, LongRef object) {
        CRYPTOKIE.CreateObject(session, templ, object);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public static long CreateObject(long session, CKA... templ) {
        return CRYPTOKIE.CreateObject(session, templ);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @see C#CopyObject(long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     */
    public static void CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        CRYPTOKIE.CopyObject(session, object, templ, newObject);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @return new object handle
     * @see C#CopyObject(long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     */
    public static long CopyObject(long session, long object, CKA... templ) {
        return CRYPTOKIE.CopyObject(session, object, templ);
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see C#DestroyObject(long, long)
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    public static void DestroyObject(long session, long object) {
        CRYPTOKIE.DestroyObject(session, object);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public static void GetObjectSize(long session, long object, LongRef size) {
        CRYPTOKIE.GetObjectSize(session, object, size);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public static long GetObjectSize(long session, long object) {
        return CRYPTOKIE.GetObjectSize(session, object);
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public static void GetAttributeValue(long session, long object, CKA... templ) {
        CRYPTOKIE.GetAttributeValue(session, object, templ);
    }

    /**
     * Obtains the value of one attributes, or returns CKA with null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public static CKA GetAttributeValue(long session, long object, long cka) {
        return CRYPTOKIE.GetAttributeValue(session, object, cka);
    }

    /**
     * Obtains the value of one or more object attributes. Sets value to null
     * if object does not include attribute.
     * @param session the session's handle
     * @param object the objects's handle
     * @param types {@link CKA} attribute types to get
     * @return attribute values
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public static CKA[] GetAttributeValue(long session, long object, long... types) {
        return CRYPTOKIE.GetAttributeValue(session, object, types);
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @see C#SetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    public static void SetAttributeValue(long session, long object, CKA... templ) {
        CRYPTOKIE.SetAttributeValue(session, object, templ);
    }

    /**
     * Initailses a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public static void FindObjectsInit(long session, CKA... templ) {
        CRYPTOKIE.FindObjectsInit(session, templ);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @see C#FindObjects(long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     */
    public static void FindObjects(long session, long[] found, LongRef objectCount) {
        CRYPTOKIE.FindObjects(session, found, objectCount);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param maxObjects maximum objects to return
     * @return list of object handles
     * @see C#FindObjects(long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     */
    public static long[] FindObjects(long session, int maxObjects) {
        return CRYPTOKIE.FindObjects(session, maxObjects);
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @see C#FindObjectsFinal(long)
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public static void FindObjectsFinal(long session) {
        CRYPTOKIE.FindObjectsFinal(session);
    }

    /**
     * Single-part search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public static long[] FindObjects(long session, CKA... templ) {
        return CRYPTOKIE.FindObjects(session, templ);
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see C#EncryptInit(long, CKM, long)
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    public static void EncryptInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.EncryptInit(session, mechanism, key);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static void Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        CRYPTOKIE.Encrypt(session, data, encryptedData, encryptedDataLen);
    }

    /**
     * Encrypts single-part data with 2 calls.  First call determines
     * size of result which may include padding, second call does encrypt.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] EncryptPad(long session, byte[] data) {
        return CRYPTOKIE.EncryptPad(session, data);
    }

    /**
     * Encrypts single-part data with single call assuming result
     * has no padding and is same size as input.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Encrypt(long session, byte[] data) {
        return CRYPTOKIE.Encrypt(session, data);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @see C#EncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static void EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        CRYPTOKIE.EncryptUpdate(session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#EncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] EncryptUpdate(long session, byte[] part) {
        return CRYPTOKIE.EncryptUpdate(session, part);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public static void EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        CRYPTOKIE.EncryptFinal(session, lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public static byte[] EncryptFinal(long session) {
        return CRYPTOKIE.EncryptFinal(session);
    }

    /**
     * Encrypts single-part data with 2 calls.  First call determines
     * size of result which may include padding, second call does encrypt.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] EncryptPad(long session, CKM mechanism, long key, byte[] data) {
        return CRYPTOKIE.EncryptPad(session, mechanism, key, data);
    }

    /**
     * Encrypts single-part data with single call assuming result
     * has no padding and is same size as input.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Encrypt(long session, CKM mechanism, long key, byte[] data) {
        return CRYPTOKIE.Encrypt(session, mechanism, key, data);
    }

    /**
     * Initialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see C#DecryptInit(long, CKM, long)
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    public static void DecryptInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.DecryptInit(session, mechanism, key);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static void Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        CRYPTOKIE.Decrypt(session, encryptedData, data, dataLen);
    }

    /**
     * Decrypts encrypted data in a single-part with 2 calls.  First call determines
     * size of result which may have padding removed, second call does decrypt.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DecryptPad(long session, byte[] encryptedData) {
        return CRYPTOKIE.DecryptPad(session, encryptedData);
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Decrypt(long session, byte[] encryptedData) {
        return CRYPTOKIE.Decrypt(session, encryptedData);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @see C#DecryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static void DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        CRYPTOKIE.DecryptUpdate(session, encryptedPart, data, dataLen);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see C#DecryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DecryptUpdate(long session, byte[] encryptedPart) {
        return CRYPTOKIE.DecryptUpdate(session, encryptedPart);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public static void DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        CRYPTOKIE.DecryptFinal(session, lastPart, lastPartLen);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public static byte[] DecryptFinal(long session) {
        return CRYPTOKIE.DecryptFinal(session);
    }

    /**
     * Decrypts encrypted data in a single-part with 2 calls.  First call determines
     * size of result which may have padding removed, second call does decrypt.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DecryptPad(long session, CKM mechanism, long key, byte[] encryptedData) {
        return CRYPTOKIE.DecryptPad(session, mechanism, key, encryptedData);
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Decrypt(long session, CKM mechanism, long key, byte[] encryptedData) {
        return CRYPTOKIE.Decrypt(session, mechanism, key, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see C#DigestInit(long, CKM)
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    public static void DigestInit(long session, CKM mechanism) {
        CRYPTOKIE.DigestInit(session, mechanism);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public static void Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        CRYPTOKIE.Digest(session, data, digest, digestLen);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Digest(long session, byte[] data) {
        return CRYPTOKIE.Digest(session, data);
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see C#DigestUpdate(long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public static void DigestUpdate(long session, byte[] part) {
        CRYPTOKIE.DigestUpdate(session, part);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see C#DigestKey(long, long)
     * @see NativeProvider#C_DigestKey(long, long)
     */
    public static void DigestKey(long session, long key) {
        CRYPTOKIE.DigestKey(session, key);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public static void DigestFinal(long session, byte[] digest, LongRef digestLen) {
        CRYPTOKIE.DigestFinal(session, digest, digestLen);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public static byte[] DigestFinal(long session) {
        return CRYPTOKIE.DigestFinal(session);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @param data data to be digested
     * @return digest
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Digest(long session, CKM mechanism, byte[] data) {
        return CRYPTOKIE.Digest(session, mechanism, data);
    }

    /**
     * Initialises a signature (private key encryption) operation, where
     * the signature is (will be) an appendix to the data, and plaintext
     * cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @see C#SignInit(long, CKM, long)
     * @see NativeProvider#C_SignInit(long, CKM, long)
     */
    public static void SignInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.SignInit(session, mechanism, key);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#Sign(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public static void Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        CRYPTOKIE.Sign(session, data, signature, signatureLen);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#Sign(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Sign(long session, byte[] data) {
        return CRYPTOKIE.Sign(session, data);
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @see C#SignUpdate(long, byte[])
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     */
    public static void SignUpdate(long session, byte[] part) {
        CRYPTOKIE.SignUpdate(session, part);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public static void SignFinal(long session, byte[] signature, LongRef signatureLen) {
        CRYPTOKIE.SignFinal(session, signature, signatureLen);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public static byte[] SignFinal(long session) {
        return CRYPTOKIE.SignFinal(session);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @param data the data to sign
     * @return signature
     * @see C#Sign(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public static byte[] Sign(long session, CKM mechanism, long key, byte[] data) {
        return CRYPTOKIE.Sign(session, mechanism, key, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see C#SignRecoverInit(long, CKM, long)
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    public static void SignRecoverInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.SignRecoverInit(session, mechanism, key);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public static void SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        CRYPTOKIE.SignRecover(session, data, signature, signatureLen);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public static byte[] SignRecover(long session, byte[] data) {
        return CRYPTOKIE.SignRecover(session, data);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public static byte[] SignRecover(long session, CKM mechanism, long key, byte[] data) {
        return CRYPTOKIE.SignRecover(session, mechanism, key, data);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyInit(long, CKM, long)
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     */
    public static void VerifyInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.VerifyInit(session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @see C#Verify(long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public static void Verify(long session, byte[] data, byte[] signature) {
        CRYPTOKIE.Verify(session, data, signature);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see C#VerifyUpdate(long, byte[])
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    public static void VerifyUpdate(long session, byte[] part) {
        CRYPTOKIE.VerifyUpdate(session, part);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see C#VerifyFinal(long, byte[])
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    public static void VerifyFinal(long session, byte[] signature) {
        CRYPTOKIE.VerifyFinal(session, signature);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @param data signed data
     * @param signature signature
     * @see C#Verify(long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public static void Verify(long session, CKM mechanism, long key, byte[] data, byte[] signature) {
        CRYPTOKIE.Verify(session, mechanism, key, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyRecoverInit(long, CKM, long)
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    public static void VerifyRecoverInit(long session, CKM mechanism, long key) {
        CRYPTOKIE.VerifyRecoverInit(session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public static void VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        CRYPTOKIE.VerifyRecover(session, signature, data, dataLen);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public static byte[] VerifyRecover(long session, byte[] signature) {
        return CRYPTOKIE.VerifyRecover(session, signature);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public static byte[] VerifyRecover(long session, CKM mechanism, long key, byte[] signature) {
        return CRYPTOKIE.VerifyRecover(session, mechanism, key, signature);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @see C#DigestEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static void DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        CRYPTOKIE.DigestEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#DigestEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DigestEncryptUpdate(long session, byte[] part) {
        return CRYPTOKIE.DigestEncryptUpdate(session, part);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @see C#DigestUpdate(long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public static void DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        CRYPTOKIE.DecryptDigestUpdate(session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptDigestUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DecryptDigestUpdate(long session, byte[] encryptedPart) {
        return CRYPTOKIE.DecryptDigestUpdate(session, encryptedPart);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @see C#SignEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static void SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        CRYPTOKIE.SignEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#SignEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] SignEncryptUpdate(long session, byte[] part) {
        return CRYPTOKIE.SignEncryptUpdate(session, part);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @see C#DecryptVerifyUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public static void DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        CRYPTOKIE.DecryptVerifyUpdate(session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptVerifyUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public static byte[] DecryptVerifyUpdate(long session, byte[] encryptedPart) {
        return CRYPTOKIE.DecryptVerifyUpdate(session, encryptedPart);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @see C#GenerateKey(long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     */
    public static void GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        CRYPTOKIE.GenerateKey(session, mechanism, templ, key);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @return key handle
     * @see C#GenerateKey(long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     */
    public static long GenerateKey(long session, CKM mechanism, CKA... templ) {
        return CRYPTOKIE.GenerateKey(session, mechanism, templ);
    }

    /**
     * Generates a public-key / private-key pair, create new key objects.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param publicKeyTemplate template for the new public key
     * @param privateKeyTemplate template for the new private key
     * @param publicKey gets handle of new public key
     * @param privateKey gets handle of new private key
     * @see C#GenerateKeyPair(long, CKM, CKA[], CKA[], LongRef, LongRef)
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, CKA[], long, CKA[], long, LongRef, LongRef)
     */
    public static void GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate,
            LongRef publicKey, LongRef privateKey) {
        CRYPTOKIE.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
    }

    /**
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @param wrappedKey gets wrapped key
     * @param wrappedKeyLen gets wrapped key length
     * @see C#WrapKey(long, CKM, long, long, byte[], LongRef)
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public static void WrapKey(long session, CKM mechanism, long wrappingKey, long key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        CRYPTOKIE.WrapKey(session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
    }

    /**
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @return wrapped key
     * @see C#WrapKey(long, CKM, long, long, byte[], LongRef)
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public static byte[] WrapKey(long session, CKM mechanism, long wrappingKey, long key) {
        return CRYPTOKIE.WrapKey(session, mechanism, wrappingKey, key);
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @param key gets new handle
     * @see C#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public static void UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        CRYPTOKIE.UnwrapKey(session, mechanism, unwrappingKey, wrappedKey, templ, key);
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @return key handle
     * @see C#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public static long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        return CRYPTOKIE.UnwrapKey(session, mechanism, unwrappingKey, wrappedKey, templ);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @param key ges new handle
     * @see C#DeriveKey(long, CKM, long, CKA[], LongRef)
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     */
    public static void DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        CRYPTOKIE.DeriveKey(session, mechanism, baseKey, templ, key);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @return new handle
     * @see C#DeriveKey(long, CKM, long, CKA[], LongRef)
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     */
    public static long DeriveKey(long session, CKM mechanism, long baseKey, CKA... templ) {
        return CRYPTOKIE.DeriveKey(session, mechanism, baseKey, templ);
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see C#SeedRandom(long, byte[])
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    public static void SeedRandom(long session, byte[] seed) {
        CRYPTOKIE.SeedRandom(session, seed);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public static void GenerateRandom(long session, byte[] randomData) {
        CRYPTOKIE.GenerateRandom(session, randomData);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public static byte[] GenerateRandom(long session, int randomLen) {
        return CRYPTOKIE.GenerateRandom(session, randomLen);
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public static void GetFunctionStatus(long session) {
        CRYPTOKIE.GetFunctionStatus(session);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public static void CancelFunction(long session) {
        CRYPTOKIE.CancelFunction(session);
    }

    /**
     * Set odd parity on buf and return updated buf.  Buf is modified in-place.
     * @param buf buf to modify in place and return
     * @return buf that was passed in
     */
    public static byte[] setOddParity(byte[] buf) {
        for (int i = 0; i < buf.length; i++) {
            int b = buf[i] & 0xff;
            b ^= b >> 4;
            b ^= b >> 2;
            b ^= b >> 1;
            buf[i] ^= (b & 1) ^ 1;
        }
        return buf;
    }

    /**
     * Resize buf to specified length. If buf already size 'newSize', then return buf, else return resized buf.
     * @param buf buf
     * @param newSize length to resize to
     * @return if buf already size 'newSize', then return buf, else return resized buf
     */
    public static byte[] resize(byte[] buf, int newSize) {
        if (buf == null || newSize >= buf.length) {
            return buf;
        }
        byte[] result = new byte[newSize];
        System.arraycopy(buf, 0, result, 0, result.length);
        return result;
    }

    /**
     * Obtain metrics for calls on underlying {@link NativeProvider}
     * @return metrics object
     */
    public static NativeProviderMetrics getMetrics() {
        return CRYPTOKIE.getMetrics();
    }
}
