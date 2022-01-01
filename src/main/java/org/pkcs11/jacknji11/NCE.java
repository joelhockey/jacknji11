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
 * This is the preferred java interface for calling cryptoki functions.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link org.pkcs11.jacknji11.NativeProvider} provides the lowest level
 * direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link org.pkcs11.jacknji11.C} provides the exact same functions
 * as {@link org.pkcs11.jacknji11.NativeProvider} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'NC.'</code> when you call the
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
 */
public class NCE {

    /**
     * Initialize cryptoki.
     * @see NC#Initialize(NativeProvider)
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     */
    static void Initialize(NativeProvider nativeProvider) {
        long rv = NC.Initialize(nativeProvider);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see NC#Finalize(NativeProvider)
     * @see NativeProvider#C_Finalize(NativePointer)
     */
    static void Finalize(NativeProvider nativeProvider) {
        long rv = NC.Finalize(nativeProvider);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see NC#GetInfo(NativeProvider, CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    static void GetInfo(NativeProvider nativeProvider, CK_INFO info) {
        long rv = NC.GetInfo(nativeProvider, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Returns general information about Cryptoki.
     * @return info
     * @see NC#GetInfo(NativeProvider, CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    static CK_INFO GetInfo(NativeProvider nativeProvider) {
        CK_INFO info = new CK_INFO();
        GetInfo(nativeProvider, info);
        return info;
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see NC#GetSlotList(NativeProvider, boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    static void GetSlotList(NativeProvider nativeProvider, boolean tokenPresent, long[] slotList, LongRef count) {
        long rv = NC.GetSlotList(nativeProvider, tokenPresent, slotList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see NC#GetSlotList(NativeProvider, boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    static long[] GetSlotList(NativeProvider nativeProvider, boolean tokenPresent) {
        LongRef count = new LongRef();
        GetSlotList(nativeProvider, tokenPresent, null, count);
        long[] result = new long[(int) count.value()];
        GetSlotList(nativeProvider, tokenPresent, result, count);
        return result;
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
    static long GetSlot(NativeProvider nativeProvider, String label) {
        long[] allslots = GetSlotList(nativeProvider, true);
        for (long slot : allslots) {
            CK_TOKEN_INFO tok = GetTokenInfo(nativeProvider, slot);
            if (tok != null && tok.label != null && new String(tok.label).trim().equals(label)) {
                return slot;
            }
        }
        throw new CKRException("No slot found with label [" + label + "]", CKR.SLOT_ID_INVALID);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @see NC#GetSlotInfo(NativeProvider, long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    static void GetSlotInfo(NativeProvider nativeProvider, long slotID, CK_SLOT_INFO info) {
        long rv = NC.GetSlotInfo(nativeProvider, slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see NC#GetSlotInfo(NativeProvider, long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    static CK_SLOT_INFO GetSlotInfo(NativeProvider nativeProvider, long slotID) {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        GetSlotInfo(nativeProvider, slotID, info);
        return info;
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see NC#GetTokenInfo(NativeProvider, long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    static void GetTokenInfo(NativeProvider nativeProvider, long slotID, CK_TOKEN_INFO info) {
        long rv = NC.GetTokenInfo(nativeProvider, slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see NC#GetTokenInfo(NativeProvider, long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    static CK_TOKEN_INFO GetTokenInfo(NativeProvider nativeProvider, long slotID) {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        GetTokenInfo(nativeProvider, slotID, info);
        return info;
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param pReserved reserved.  Should be null
     * @see NC#WaitForSlotEvent(NativeProvider, long, LongRef, NativePointer)
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    static void WaitForSlotEvent(NativeProvider nativeProvider, long flags, LongRef slot, NativePointer pReserved) {
        long rv = NC.WaitForSlotEvent(nativeProvider, flags, slot, pReserved);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see NC#GetMechanismList(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    static void GetMechanismList(NativeProvider nativeProvider, long slotID, long[] mechanismList, LongRef count) {
        long rv = NC.GetMechanismList(nativeProvider, slotID, mechanismList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see NC#GetMechanismList(NativeProvider, long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    static long[] GetMechanismList(NativeProvider nativeProvider, long slotID) {
        LongRef count = new LongRef();
        GetMechanismList(nativeProvider, slotID, null, count);
        long[] mechanisms = new long[(int) count.value()];
        GetMechanismList(nativeProvider, slotID, mechanisms, count);
        return mechanisms;
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see NC#GetMechanismInfo(NativeProvider, long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    static void GetMechanismInfo(NativeProvider nativeProvider, long slotID, long type, CK_MECHANISM_INFO info) {
        long rv = NC.GetMechanismInfo(nativeProvider, slotID, type, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see NC#GetMechanismInfo(NativeProvider, long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    static CK_MECHANISM_INFO GetMechanismInfo(NativeProvider nativeProvider, long slotID, long type) {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        GetMechanismInfo(nativeProvider, slotID, type, info);
        return info;
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
    static void InitToken(NativeProvider nativeProvider, long slotID, byte[] pin, byte[] label) {
        long rv = NC.InitToken(nativeProvider, slotID, pin, label);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see NC#InitPIN(NativeProvider, long, byte[])
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    static void InitPIN(NativeProvider nativeProvider, long session, byte[] pin) {
        long rv = NC.InitPIN(nativeProvider, session, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see NC#SetPIN(NativeProvider, long, byte[], byte[])
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    static void SetPIN(NativeProvider nativeProvider, long session, byte[] oldPin, byte[] newPin) {
        long rv = NC.SetPIN(nativeProvider, session, oldPin, newPin);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void OpenSession(NativeProvider nativeProvider, long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        long rv = NC.OpenSession(nativeProvider, slotID, flags, application, notify, session);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long OpenSession(NativeProvider nativeProvider, long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        LongRef session = new LongRef();
        OpenSession(nativeProvider, slotID, flags, application, notify, session);
        return session.value();
    }

    /**
     * Opens a session between an application and a token using {@link CK_SESSION_INFO#CKF_RW_SESSION and CK_SESSION_INFO#CKF_SERIAL_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see NC#OpenSession(NativeProvider, long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    static long OpenSession(NativeProvider nativeProvider, long slotID) {
        return OpenSession(nativeProvider, slotID, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see NC#CloseSession(NativeProvider, long)
     * @see NativeProvider#C_CloseSession(long)
     */
    static void CloseSession(NativeProvider nativeProvider, long session) {
        long rv = NC.CloseSession(nativeProvider, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see NC#CloseAllSessions(NativeProvider, long)
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    static void CloseAllSessions(NativeProvider nativeProvider, long slotID) {
        long rv = NC.CloseAllSessions(nativeProvider, slotID);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see NC#GetSessionInfo(NativeProvider, long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    static void GetSessionInfo(NativeProvider nativeProvider, long session, CK_SESSION_INFO info) {
        long rv = NC.GetSessionInfo(nativeProvider, session, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see NC#GetSessionInfo(NativeProvider, long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    static CK_SESSION_INFO GetSessionInfo(NativeProvider nativeProvider, long session) {
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        GetSessionInfo(nativeProvider, session, info);
        return info;
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see NC#GetOperationState(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    static void GetOperationState(NativeProvider nativeProvider, long session, byte[] operationState, LongRef operationStateLen) {
        long rv = NC.GetOperationState(nativeProvider, session, operationState, operationStateLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see NC#GetOperationState(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    static byte[] GetOperationState(NativeProvider nativeProvider, long session) {
        LongRef len = new LongRef();
        GetOperationState(nativeProvider, session, null, len);
        byte[] result = new byte[(int) len.value()];
        GetOperationState(nativeProvider, session, result, len);
        return resize(result, (int) len.value());
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
    static void SetOperationState(NativeProvider nativeProvider, long session, byte[] operationState, long encryptionKey, long authenticationKey) {
        long rv = NC.SetOperationState(nativeProvider, session, operationState, encryptionKey, authenticationKey);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Logs a user into a token.  Ignores CKR=0x00000100: USER_ALREADY_LOGGED_IN
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    static void Login(NativeProvider nativeProvider, long session, long userType, byte[] pin) {
        long rv = NC.Login(nativeProvider, session, userType, pin);
        if (rv != CKR.OK && rv != CKR.USER_ALREADY_LOGGED_IN) throw new CKRException(rv);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    static void LoginUser(NativeProvider nativeProvider, long session, byte[] pin) {
        Login(nativeProvider, session, CKU.USER, pin);
    }

    /**
     * Los a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN encoded in a single byte encoding format such as ISO8859-1
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    static void LoginUser(NativeProvider nativeProvider, long session, String pin) {
        LoginUser(nativeProvider, session, Buf.c2b(pin));
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    static void LoginSO(NativeProvider nativeProvider, long session, byte[] pin) {
        Login(nativeProvider, session, CKU.SO, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN encoded in a single byte encoding format such as ISO8859-1
     * @see NC#Login(NativeProvider, long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    static void LoginSO(NativeProvider nativeProvider, long session, String pin) {
        LoginSO(nativeProvider, session, Buf.c2b(pin));
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see NC#Logout(NativeProvider, long)
     * @see NativeProvider#C_Logout(long)
     */
    static void Logout(NativeProvider nativeProvider, long session) {
        long rv = NC.Logout(nativeProvider, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see NC#CreateObject(NativeProvider, long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    static void CreateObject(NativeProvider nativeProvider, long session, CKA[] templ, LongRef object) {
        long rv = NC.CreateObject(nativeProvider, session, templ, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see NC#CreateObject(NativeProvider, long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    static long CreateObject(NativeProvider nativeProvider, long session, CKA... templ) {
        LongRef object = new LongRef();
        CreateObject(nativeProvider, session, templ, object);
        return object.value();
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
    static void CopyObject(NativeProvider nativeProvider, long session, long object, CKA[] templ, LongRef newObject) {
        long rv = NC.CopyObject(nativeProvider, session, object, templ, newObject);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long CopyObject(NativeProvider nativeProvider, long session, long object, CKA... templ) {
        LongRef newObject = new LongRef();
        CopyObject(nativeProvider, session, object, templ, newObject);
        return newObject.value();
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see NC#DestroyObject(NativeProvider, long, long)
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    static void DestroyObject(NativeProvider nativeProvider, long session, long object) {
        long rv = NC.DestroyObject(nativeProvider, session, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see NC#GetObjectSize(NativeProvider, long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    static void GetObjectSize(NativeProvider nativeProvider, long session, long object, LongRef size) {
        long rv = NC.GetObjectSize(nativeProvider, session, object, size);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see NC#GetObjectSize(NativeProvider, long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    static long GetObjectSize(NativeProvider nativeProvider, long session, long object) {
        LongRef size = new LongRef();
        GetObjectSize(nativeProvider, session, object, size);
        return size.value();
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @see NC#GetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    static void GetAttributeValue(NativeProvider nativeProvider, long session, long object, CKA... templ) {
        if (templ == null || templ.length == 0) {
            return;
        }
        long rv = NC.GetAttributeValue(nativeProvider, session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains the value of one attributes, or returns CKA with null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see NC#GetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    static CKA GetAttributeValue(NativeProvider nativeProvider, long session, long object, long cka) {
        CKA[] templ = {new CKA(cka)};
        long rv = NC.GetAttributeValue(nativeProvider, session, object, templ);
        if (rv == CKR.ATTRIBUTE_TYPE_INVALID || templ[0].ulValueLen == 0) {
            return templ[0];
        }
        if (rv != CKR.OK) throw new CKRException(rv);

        // allocate memory and call again
        templ[0].pValue = new byte[(int) templ[0].ulValueLen];
        rv = NC.GetAttributeValue(nativeProvider, session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        return templ[0];
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
    static CKA[] GetAttributeValue(NativeProvider nativeProvider, long session, long object, long... types) {
        if (types == null || types.length == 0) {
            return new CKA[0];
        }
        CKA[] templ = new CKA[types.length];
        for (int i = 0; i < types.length; i++) {
            templ[i] = new CKA(types[i], null);
        }

        // try getting all at once
        try {
            GetAttributeValue(nativeProvider, session, object, templ);
            // allocate memory and go again
            for (CKA att : templ) {
                att.pValue = att.ulValueLen > 0 ? new byte[(int) att.ulValueLen] : null;
            }
            GetAttributeValue(nativeProvider, session, object, templ);
            return templ;
        } catch (CKRException ckre) {
            // if we got CKR_ATTRIBUTE_TYPE_INVALID, then handle below
            if (ckre.getCKR() != CKR.ATTRIBUTE_TYPE_INVALID) {
                throw ckre;
            }
        }

        // send gets one at a time
        CKA[] result = new CKA[types.length];
        for (int i = 0; i < types.length; i++) {
            result[i] = GetAttributeValue(nativeProvider, session, object, types[i]);
        }
        return result;
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @see NC#SetAttributeValue(NativeProvider, long, long, CKA[])
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    static void SetAttributeValue(NativeProvider nativeProvider, long session, long object, CKA... templ) {
        long rv = NC.SetAttributeValue(nativeProvider, session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initialises a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see NC#FindObjectsInit(NativeProvider, long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    static void FindObjectsInit(NativeProvider nativeProvider, long session, CKA... templ) {
        long rv = NC.FindObjectsInit(nativeProvider, session, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void FindObjects(NativeProvider nativeProvider, long session, long[] found, LongRef objectCount) {
        long rv = NC.FindObjects(nativeProvider, session, found, objectCount);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long[] FindObjects(NativeProvider nativeProvider, long session, int maxObjects) {
        long[] found = new long[maxObjects];
        LongRef len = new LongRef();
        FindObjects(nativeProvider, session, found, len);
        long count = len.value();
        if (count == maxObjects) {
            return found;
        } else {
            long[] result = new long[(int) count];
            System.arraycopy(found, 0, result, 0, result.length);
            return result;
        }
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @see NC#FindObjectsFinal(NativeProvider, long)
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    static void FindObjectsFinal(NativeProvider nativeProvider, long session) {
        long rv = NC.FindObjectsFinal(nativeProvider, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Single-part search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see NC#FindObjectsInit(NativeProvider, long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    static long[] FindObjects(NativeProvider nativeProvider, long session, CKA... templ) {
        FindObjectsInit(nativeProvider, session, templ);
        int maxObjects = 1024;
        // call once
        long[] result = FindObjects(nativeProvider, session, maxObjects);
        // most likely we are done now
        if (result.length < maxObjects) {
            FindObjectsFinal(nativeProvider, session);
            return result;
        }

        // this is a lot of objects!
        while (true) {
            maxObjects *= 2;
            long[] found = FindObjects(nativeProvider, session, maxObjects);
            long[] temp = new long[result.length + found.length];
            System.arraycopy(result, 0, temp, 0, result.length);
            System.arraycopy(found, 0, temp, result.length, found.length);
            result = temp;
            if (found.length < maxObjects) { // exhausted
                FindObjectsFinal(nativeProvider, session);
                return result;
            }
        }
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see NC#EncryptInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    static void EncryptInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.EncryptInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Encrypt(NativeProvider nativeProvider, long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        long rv = NC.Encrypt(nativeProvider, session, data, encryptedData, encryptedDataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static byte[] EncryptPad(NativeProvider nativeProvider, long session, byte[] data) {
        LongRef l = new LongRef();
        Encrypt(nativeProvider, session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Encrypt(nativeProvider, session, data, result, l);
        return resize(result, (int) l.value());
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
    static byte[] Encrypt(NativeProvider nativeProvider, long session, byte[] data) {
        byte[] result = new byte[data.length];
        LongRef l = new LongRef(result.length);
        Encrypt(nativeProvider, session, data, result, l);
        return resize(result, (int) l.value);
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
    static void EncryptUpdate(NativeProvider nativeProvider, long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = NC.EncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#EncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] EncryptUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        LongRef l = new LongRef();
        EncryptUpdate(nativeProvider, session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        EncryptUpdate(nativeProvider, session, part, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see NC#EncryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    static void EncryptFinal(NativeProvider nativeProvider, long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        long rv = NC.EncryptFinal(nativeProvider, session, lastEncryptedPart, lastEncryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see NC#EncryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    static byte[] EncryptFinal(NativeProvider nativeProvider, long session) {
        LongRef l = new LongRef();
        EncryptFinal(nativeProvider, session, null, l);
        byte[] result = new byte[(int) l.value()];
        EncryptFinal(nativeProvider, session, result, l);
        return resize(result, (int) l.value());
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
    static byte[] EncryptPad(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] data) {
        EncryptInit(nativeProvider, session, mechanism, key);
        return EncryptPad(nativeProvider, session, data);
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
    static byte[] Encrypt(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] data) {
        EncryptInit(nativeProvider, session, mechanism, key);
        return Encrypt(nativeProvider, session, data);
    }

    /**
     * Initialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see NC#DecryptInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    static void DecryptInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.DecryptInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Decrypt(NativeProvider nativeProvider, long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        long rv = NC.Decrypt(nativeProvider, session, encryptedData, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static byte[] DecryptPad(NativeProvider nativeProvider, long session, byte[] encryptedData) {
        LongRef l = new LongRef();
        Decrypt(nativeProvider, session, encryptedData, null, l);
        byte[] result = new byte[(int) l.value()];
        Decrypt(nativeProvider, session, encryptedData, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param encryptedData ciphertext
     * @return plaintext
     * @see NC#Decrypt(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    static byte[] Decrypt(NativeProvider nativeProvider, long session, byte[] encryptedData) {
        byte[] result = new byte[encryptedData.length];
        LongRef l = new LongRef(result.length);
        Decrypt(nativeProvider, session, encryptedData, result, l);
        return resize(result, (int) l.value());
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
    static void DecryptUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        long rv = NC.DecryptUpdate(nativeProvider, session, encryptedPart, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see NC#DecryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] DecryptUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptUpdate(nativeProvider, session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptUpdate(nativeProvider, session, encryptedPart, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see NC#DecryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    static void DecryptFinal(NativeProvider nativeProvider, long session, byte[] lastPart, LongRef lastPartLen) {
        long rv = NC.DecryptFinal(nativeProvider, session, lastPart, lastPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see NC#DecryptFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    static byte[] DecryptFinal(NativeProvider nativeProvider, long session) {
        LongRef l = new LongRef();
        DecryptFinal(nativeProvider, session, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptFinal(nativeProvider, session, result, l);
        return resize(result, (int) l.value());
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
    static byte[] DecryptPad(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] encryptedData) {
        DecryptInit(nativeProvider, session, mechanism, key);
        return DecryptPad(nativeProvider, session, encryptedData);
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
    static byte[] Decrypt(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] encryptedData) {
        DecryptInit(nativeProvider, session, mechanism, key);
        return Decrypt(nativeProvider, session, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see NC#DigestInit(NativeProvider, long, CKM)
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    static void DigestInit(NativeProvider nativeProvider, long session, CKM mechanism) {
        long rv = NC.DigestInit(nativeProvider, session, mechanism);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Digest(NativeProvider nativeProvider, long session, byte[] data, byte[] digest, LongRef digestLen) {
        long rv = NC.Digest(nativeProvider, session, data, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see NC#Digest(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    static byte[] Digest(NativeProvider nativeProvider, long session, byte[] data) {
        LongRef l = new LongRef();
        Digest(nativeProvider, session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Digest(nativeProvider, session, data, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see NC#DigestUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    static void DigestUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        long rv = NC.DigestUpdate(nativeProvider, session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see NC#DigestKey(NativeProvider, long, long)
     * @see NativeProvider#C_DigestKey(long, long)
     */
    static void DigestKey(NativeProvider nativeProvider, long session, long key) {
        long rv = NC.DigestKey(nativeProvider, session, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see NC#DigestFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    static void DigestFinal(NativeProvider nativeProvider, long session, byte[] digest, LongRef digestLen) {
        long rv = NC.DigestFinal(nativeProvider, session, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see NC#DigestFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    static byte[] DigestFinal(NativeProvider nativeProvider, long session) {
        LongRef l = new LongRef();
        DigestFinal(nativeProvider, session, null, l);
        byte[] result = new byte[(int) l.value()];
        DigestFinal(nativeProvider, session, result, l);
        return resize(result, (int) l.value());
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
    static byte[] Digest(NativeProvider nativeProvider, long session, CKM mechanism, byte[] data) {
        DigestInit(nativeProvider, session, mechanism);
        return Digest(nativeProvider, session, data);
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
    static void SignInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.SignInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Sign(NativeProvider nativeProvider, long session, byte[] data, byte[] signature, LongRef signatureLen) {
        long rv = NC.Sign(nativeProvider, session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static byte[] Sign(NativeProvider nativeProvider, long session, byte[] data) {
        LongRef l = new LongRef();
        Sign(nativeProvider, session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Sign(nativeProvider, session, data, result, l);
        return resize(result, (int) l.value());
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
    static void SignUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        long rv = NC.SignUpdate(nativeProvider, session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see NC#SignFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    static void SignFinal(NativeProvider nativeProvider, long session, byte[] signature, LongRef signatureLen) {
        long rv = NC.SignFinal(nativeProvider, session, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see NC#SignFinal(NativeProvider, long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    static byte[] SignFinal(NativeProvider nativeProvider, long session) {
        LongRef l = new LongRef();
        SignFinal(nativeProvider, session, null, l);
        byte[] result = new byte[(int) l.value()];
        SignFinal(nativeProvider, session, result, l);
        return resize(result, (int) l.value());
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
    static byte[] Sign(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] data) {
        SignInit(nativeProvider, session, mechanism, key);
        return Sign(nativeProvider, session, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see NC#SignRecoverInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    static void SignRecoverInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.SignRecoverInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void SignRecover(NativeProvider nativeProvider, long session, byte[] data, byte[] signature, LongRef signatureLen) {
        long rv = NC.SignRecover(nativeProvider, session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see NC#SignRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    static byte[] SignRecover(NativeProvider nativeProvider, long session, byte[] data) {
        LongRef l = new LongRef();
        SignRecover(nativeProvider, session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        SignRecover(nativeProvider, session, data, result, l);
        return resize(result, (int) l.value());
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
    static byte[] SignRecover(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] data) {
        SignRecoverInit(nativeProvider, session, mechanism, key);
        return SignRecover(nativeProvider, session, data);
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
    static void VerifyInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.VerifyInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Verify(NativeProvider nativeProvider, long session, byte[] data, byte[] signature) {
        long rv = NC.Verify(nativeProvider, session, data, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see NC#VerifyUpdate(NativeProvider, long, byte[])
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    static void VerifyUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        long rv = NC.VerifyUpdate(nativeProvider, session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see NC#VerifyFinal(NativeProvider, long, byte[])
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    static void VerifyFinal(NativeProvider nativeProvider, long session, byte[] signature) {
        long rv = NC.VerifyFinal(nativeProvider, session, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void Verify(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] data, byte[] signature) {
        VerifyInit(nativeProvider, session, mechanism, key);
        Verify(nativeProvider, session, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see NC#VerifyRecoverInit(NativeProvider, long, CKM, long)
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    static void VerifyRecoverInit(NativeProvider nativeProvider, long session, CKM mechanism, long key) {
        long rv = NC.VerifyRecoverInit(nativeProvider, session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void VerifyRecover(NativeProvider nativeProvider, long session, byte[] signature, byte[] data, LongRef dataLen) {
        long rv = NC.VerifyRecover(nativeProvider, session, signature, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see NC#VerifyRecover(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    static byte[] VerifyRecover(NativeProvider nativeProvider, long session, byte[] signature) {
        LongRef l = new LongRef();
        VerifyRecover(nativeProvider, session, signature, null, l);
        byte[] result = new byte[(int) l.value()];
        VerifyRecover(nativeProvider, session, signature, result, l);
        return resize(result, (int) l.value());
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
    static byte[] VerifyRecover(NativeProvider nativeProvider, long session, CKM mechanism, long key, byte[] signature) {
        VerifyRecoverInit(nativeProvider, session, mechanism, key);
        return VerifyRecover(nativeProvider, session, signature);
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
    static void DigestEncryptUpdate(NativeProvider nativeProvider, long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = NC.DigestEncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#DigestEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] DigestEncryptUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        LongRef l = new LongRef();
        DigestEncryptUpdate(nativeProvider, session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        DigestEncryptUpdate(nativeProvider, session, part, result, l);
        return resize(result, (int) l.value());
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
    static void DecryptDigestUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        long rv = NC.DecryptDigestUpdate(nativeProvider, session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see NC#DecryptDigestUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] DecryptDigestUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptDigestUpdate(nativeProvider, session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptDigestUpdate(nativeProvider, session, encryptedPart, result, l);
        return resize(result, (int) l.value());
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
    static void SignEncryptUpdate(NativeProvider nativeProvider, long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = NC.SignEncryptUpdate(nativeProvider, session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see NC#SignEncryptUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] SignEncryptUpdate(NativeProvider nativeProvider, long session, byte[] part) {
        LongRef l = new LongRef();
        SignEncryptUpdate(nativeProvider, session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        SignEncryptUpdate(nativeProvider, session, part, result, l);
        return resize(result, (int) l.value());
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
    static void DecryptVerifyUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        long rv = NC.DecryptVerifyUpdate(nativeProvider, session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see NC#DecryptVerifyUpdate(NativeProvider, long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    static byte[] DecryptVerifyUpdate(NativeProvider nativeProvider, long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptVerifyUpdate(nativeProvider, session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptVerifyUpdate(nativeProvider, session, encryptedPart, result, l);
        return resize(result, (int) l.value());
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
    static void GenerateKey(NativeProvider nativeProvider, long session, CKM mechanism, CKA[] templ, LongRef key) {
        long rv = NC.GenerateKey(nativeProvider, session, mechanism, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long GenerateKey(NativeProvider nativeProvider, long session, CKM mechanism, CKA... templ) {
        LongRef key = new LongRef();
        GenerateKey(nativeProvider, session, mechanism, templ, key);
        return key.value();
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
    static void GenerateKeyPair(NativeProvider nativeProvider, long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate,
                                LongRef publicKey, LongRef privateKey) {
        long rv = NC.GenerateKeyPair(nativeProvider, session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static void WrapKey(NativeProvider nativeProvider, long session, CKM mechanism, long wrappingKey, long key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        long rv = NC.WrapKey(nativeProvider, session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static byte[] WrapKey(NativeProvider nativeProvider, long session, CKM mechanism, long wrappingKey, long key) {
        LongRef l = new LongRef();
        WrapKey(nativeProvider, session, mechanism, wrappingKey, key, null, l);
        byte[] result = new byte[(int) l.value()];
        WrapKey(nativeProvider, session, mechanism, wrappingKey, key, result, l);
        return resize(result, (int) l.value());
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
    static void UnwrapKey(NativeProvider nativeProvider, long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        long rv = NC.UnwrapKey(nativeProvider, session, mechanism, unwrappingKey, wrappedKey, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long UnwrapKey(NativeProvider nativeProvider, long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        LongRef result = new LongRef();
        UnwrapKey(nativeProvider, session, mechanism, unwrappingKey, wrappedKey, templ, result);
        return result.value();
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
    static void DeriveKey(NativeProvider nativeProvider, long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        long rv = NC.DeriveKey(nativeProvider, session, mechanism, baseKey, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    static long DeriveKey(NativeProvider nativeProvider, long session, CKM mechanism, long baseKey, CKA... templ) {
        LongRef key = new LongRef();
        DeriveKey(nativeProvider, session, mechanism, baseKey, templ, key);
        return key.value();
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see NC#SeedRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    static void SeedRandom(NativeProvider nativeProvider, long session, byte[] seed) {
        long rv = NC.SeedRandom(nativeProvider, session, seed);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see NC#GenerateRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    static void GenerateRandom(NativeProvider nativeProvider, long session, byte[] randomData) {
        long rv = NC.GenerateRandom(nativeProvider, session, randomData);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see NC#GenerateRandom(NativeProvider, long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    static byte[] GenerateRandom(NativeProvider nativeProvider, long session, int randomLen) {
        byte[] result = new byte[randomLen];
        GenerateRandom(nativeProvider, session, result);
        return result;
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see NC#GetFunctionStatus(NativeProvider, long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    static void GetFunctionStatus(NativeProvider nativeProvider, long session) {
        long rv = NC.GetFunctionStatus(nativeProvider, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see NC#GetFunctionStatus(NativeProvider, long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    static void CancelFunction(NativeProvider nativeProvider, long session) {
        long rv = NC.CancelFunction(nativeProvider, session);
        if (rv != CKR.OK) throw new CKRException(rv);
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
}
