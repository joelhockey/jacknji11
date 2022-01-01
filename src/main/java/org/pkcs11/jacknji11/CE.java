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
 * @deprecated Use the {@link CEi} class instead
 */
@Deprecated
public class CE {

    /**
     * Initialize cryptoki.
     * @see C#Initialize()
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @deprecated use {@link CEi#Initialize()} instead
     */
    @Deprecated
    public static void Initialize() {
        if (C.NATIVE == null) {
            C.NATIVE = new JNA();
        }
        NCE.Initialize(C.NATIVE);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see C#Finalize()
     * @see NativeProvider#C_Finalize(NativePointer)
     * @deprecated use {@link CEi#Finalize()} instead
     */
    @Deprecated
    public static void Finalize() {
        NCE.Finalize(C.NATIVE);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     * @deprecated use {@link CEi#GetInfo(CK_INFO)} instead
     */
    @Deprecated
    public static void GetInfo(CK_INFO info) {
        NCE.GetInfo(C.NATIVE, info);
    }

    /**
     * Returns general information about Cryptoki.
     * @return info
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     * @deprecated use {@link CEi#GetInfo()} instead
     */
    @Deprecated
    public static CK_INFO GetInfo() {
        return NCE.GetInfo(C.NATIVE);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @deprecated use {@link CEi#GetSlotList(boolean, long[], LongRef)} instead
     */
    @Deprecated
    public static void GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        NCE.GetSlotList(C.NATIVE, tokenPresent, slotList, count);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @deprecated use {@link CEi#GetSlotList(boolean)} instead
     */
    @Deprecated
    public static long[] GetSlotList(boolean tokenPresent) {
        return NCE.GetSlotList(C.NATIVE, tokenPresent);
    }

    /**
     * Return first slot with given label else throw CKRException.
     * @param label label of slot to find
     * @return slot id or CKRException if no slot found
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     * @deprecated use {@link CEi#GetSlot(String)} instead
     */
    @Deprecated
    public static long GetSlot(String label) {
        return NCE.GetSlot(C.NATIVE, label);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     * @deprecated use {@link CEi#GetSlotInfo(long, CK_SLOT_INFO)} instead
     */
    @Deprecated
    public static void GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        NCE.GetSlotInfo(C.NATIVE, slotID, info);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     * @deprecated use {@link CEi#GetSlotInfo(long)} instead
     */
    @Deprecated
    public static CK_SLOT_INFO GetSlotInfo(long slotID) {
        return NCE.GetSlotInfo(C.NATIVE, slotID);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     * @deprecated use {@link CEi#GetTokenInfo(long, CK_TOKEN_INFO)} instead
     */
    @Deprecated
    public static void GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        NCE.GetTokenInfo(C.NATIVE, slotID, info);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     * @deprecated use {@link CEi#GetTokenInfo(long)} instead
     */
    @Deprecated
    public static CK_TOKEN_INFO GetTokenInfo(long slotID) {
        return NCE.GetTokenInfo(C.NATIVE, slotID);
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param pReserved reserved.  Should be null
     * @see C#WaitForSlotEvent(long, LongRef, NativePointer)
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     * @deprecated use {@link CEi#WaitForSlotEvent(long, LongRef, NativePointer)} instead
     */
    @Deprecated
    public static void WaitForSlotEvent(long flags, LongRef slot, NativePointer pReserved) {
        NCE.WaitForSlotEvent(C.NATIVE, flags, slot, pReserved);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     * @deprecated use {@link CEi#GetMechanismList(long, long[], LongRef)} instead
     */
    @Deprecated
    public static void GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        NCE.GetMechanismList(C.NATIVE, slotID, mechanismList, count);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     * @deprecated use {@link CEi#GetMechanismList(long)} instead
     */
    @Deprecated
    public static long[] GetMechanismList(long slotID) {
        return NCE.GetMechanismList(C.NATIVE, slotID);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @deprecated use {@link CEi#GetMechanismInfo(long, long, CK_MECHANISM_INFO)} instead
     */
    @Deprecated
    public static void GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        NCE.GetMechanismInfo(C.NATIVE, slotID, type, info);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @deprecated use {@link CEi#GetMechanismInfo(long, long)} instead
     */
    @Deprecated
    public static CK_MECHANISM_INFO GetMechanismInfo(long slotID, long type) {
        return NCE.GetMechanismInfo(C.NATIVE, slotID, type);
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's initial PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @see C#InitToken(long, byte[], byte[])
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     * @deprecated use {@link CEi#InitToken(long, byte[], byte[])} instead
     */
    @Deprecated
    public static void InitToken(long slotID, byte[] pin, byte[] label) {
        NCE.InitToken(C.NATIVE, slotID, pin, label);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#InitPIN(long, byte[])
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     * @deprecated use {@link CEi#InitPIN(long, byte[])} instead
     */
    @Deprecated
    public static void InitPIN(long session, byte[] pin) {
        NCE.InitPIN(C.NATIVE, session, pin);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see C#SetPIN(long, byte[], byte[])
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     * @deprecated use {@link CEi#SetPIN(long, byte[], byte[])} instead
     */
    @Deprecated
    public static void SetPIN(long session, byte[] oldPin, byte[] newPin) {
        NCE.SetPIN(C.NATIVE, session, oldPin, newPin);
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
     * @deprecated use {@link CEi#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)} instead
     */
    @Deprecated
    public static void OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        NCE.OpenSession(C.NATIVE, slotID, flags, application, notify, session);
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
     * @deprecated use {@link CEi#OpenSession(long, long, NativePointer, CK_NOTIFY)} instead
     */
    @Deprecated
    public static long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        return NCE.OpenSession(C.NATIVE, slotID, flags, application, notify);
    }

    /**
     * Opens a session between an application and a token using {@link CK_SESSION_INFO#CKF_RW_SESSION and CK_SESSION_INFO#CKF_SERIAL_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see C#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @deprecated use {@link CEi#OpenSession(long)} instead
     */
    @Deprecated
    public static long OpenSession(long slotID) {
        return NCE.OpenSession(C.NATIVE, slotID);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see C#CloseSession(long)
     * @see NativeProvider#C_CloseSession(long)
     * @deprecated use {@link CEi#CloseSession(long)} instead
     */
    @Deprecated
    public static void CloseSession(long session) {
        NCE.CloseSession(C.NATIVE, session);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see C#CloseAllSessions(long)
     * @see NativeProvider#C_CloseAllSessions(long)
     * @deprecated use {@link CEi#CloseAllSessions(long)} instead
     */
    @Deprecated
    public static void CloseAllSessions(long slotID) {
        NCE.CloseAllSessions(C.NATIVE, slotID);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     * @deprecated use {@link CEi#GetSessionInfo(long, CK_SESSION_INFO)} instead
     */
    @Deprecated
    public static void GetSessionInfo(long session, CK_SESSION_INFO info) {
        NCE.GetSessionInfo(C.NATIVE, session, info);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     * @deprecated use {@link CEi#GetSessionInfo(long)} instead
     */
    @Deprecated
    public static CK_SESSION_INFO GetSessionInfo(long session) {
        return NCE.GetSessionInfo(C.NATIVE, session);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     * @deprecated use {@link CEi#GetObjectSize(long, long, LongRef)} instead
     */
    @Deprecated
    public static void GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        NCE.GetOperationState(C.NATIVE, session, operationState, operationStateLen);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     * @deprecated use {@link CEi#GetOperationState(long)} instead
     */
    @Deprecated
    public static byte[] GetOperationState(long session) {
        return NCE.GetOperationState(C.NATIVE, session);
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @see C#SetOperationState(long, byte[], long, long)
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     * @deprecated use {@link CEi#SetOperationState(long, byte[], long, long)} instead
     */
    @Deprecated
    public static void SetOperationState(long session, byte[] operationState, long encryptionKey, long authenticationKey) {
        NCE.SetOperationState(C.NATIVE, session, operationState, encryptionKey, authenticationKey);
    }

    /**
     * Logs a user into a token.  Ignores CKR=0x00000100: USER_ALREADY_LOGGED_IN
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link CEi#Login(long, long, byte[])} instead
     */
    @Deprecated
    public static void Login(long session, long userType, byte[] pin) {
        NCE.Login(C.NATIVE, session, userType, pin);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link CEi#LoginUser(long, byte[])} instead
     */
    @Deprecated
    public static void LoginUser(long session, byte[] pin) {
        NCE.LoginUser(C.NATIVE, session, pin);
    }

    /**
     * Los a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link CEi#LoginUser(long, String)} instead
     */
    @Deprecated
    public static void LoginUser(long session, String pin) {
        NCE.LoginUser(C.NATIVE, session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link CEi#LoginSO(long, byte[])} instead
     */
    @Deprecated
    public static void LoginSO(long session, byte[] pin) {
        NCE.LoginSO(C.NATIVE, session, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     * @deprecated use {@link CEi#LoginSO(long, String)} instead
     */
    @Deprecated
    public static void LoginSO(long session, String pin) {
        NCE.LoginSO(C.NATIVE, session, pin);
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see C#Logout(long)
     * @see NativeProvider#C_Logout(long)
     * @deprecated use {@link CEi#Logout(long)} instead
     */
    @Deprecated
    public static void Logout(long session) {
        NCE.Logout(C.NATIVE, session);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     * @deprecated use {@link CEi#CreateObject(long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static void CreateObject(long session, CKA[] templ, LongRef object) {
        NCE.CreateObject(C.NATIVE, session, templ, object);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     * @deprecated use {@link CEi#CreateObject(long, CKA...)} instead
     */
    @Deprecated
    public static long CreateObject(long session, CKA... templ) {
        return NCE.CreateObject(C.NATIVE, session, templ);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @see C#CopyObject(long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     * @deprecated use {@link CEi#CopyObject(long, long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static void CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        NCE.CopyObject(C.NATIVE, session, object, templ, newObject);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @return new object handle
     * @see C#CopyObject(long, long, CKA[], LongRef)
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     * @deprecated use {@link CEi#CopyObject(long, long, CKA...)} instead
     */
    @Deprecated
    public static long CopyObject(long session, long object, CKA... templ) {
        return NCE.CopyObject(C.NATIVE, session, object, templ);
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see C#DestroyObject(long, long)
     * @see NativeProvider#C_DestroyObject(long, long)
     * @deprecated use {@link CEi#DestroyObject(long, long)} instead
     */
    @Deprecated
    public static void DestroyObject(long session, long object) {
        NCE.DestroyObject(C.NATIVE, session, object);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     * @deprecated use {@link CEi#GetObjectSize(long, long, LongRef)} instead
     */
    @Deprecated
    public static void GetObjectSize(long session, long object, LongRef size) {
        NCE.GetObjectSize(C.NATIVE, session, object, size);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     * @deprecated use {@link CEi#GetObjectSize(long, long)} instead
     */
    @Deprecated
    public static long GetObjectSize(long session, long object) {
        return NCE.GetObjectSize(C.NATIVE, session, object);
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     * @deprecated use {@link CEi#GetAttributeValue(long, long, CKA...)} instead
     */
    @Deprecated
    public static void GetAttributeValue(long session, long object, CKA... templ) {
        NCE.GetAttributeValue(C.NATIVE, session, object, templ);
    }

    /**
     * Obtains the value of one attributes, or returns CKA with null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     * @deprecated use {@link CEi#GetAttributeValue(long, long, long)} instead
     */
    @Deprecated
    public static CKA GetAttributeValue(long session, long object, long cka) {
        return NCE.GetAttributeValue(C.NATIVE, session, object, cka);
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
     * @deprecated use {@link CEi#GetAttributeValue(long, long, long...)} instead
     */
    @Deprecated
    public static CKA[] GetAttributeValue(long session, long object, long... types) {
        return NCE.GetAttributeValue(C.NATIVE, session, object, types);
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @see C#SetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     * @deprecated use {@link CEi#SetAttributeValue(long, long, CKA...)} instead
     */
    @Deprecated
    public static void SetAttributeValue(long session, long object, CKA... templ) {
        NCE.SetAttributeValue(C.NATIVE, session, object, templ);
    }

    /**
     * Initialises a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     * @deprecated use {@link CEi#FindObjectsInit(long, CKA...)} instead
     */
    @Deprecated
    public static void FindObjectsInit(long session, CKA... templ) {
        NCE.FindObjectsInit(C.NATIVE, session, templ);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @see C#FindObjects(long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     * @deprecated use {@link CEi#FindObjects(long, long[], LongRef)} instead
     */
    @Deprecated
    public static void FindObjects(long session, long[] found, LongRef objectCount) {
        NCE.FindObjects(C.NATIVE, session, found, objectCount);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param maxObjects maximum objects to return
     * @return list of object handles
     * @see C#FindObjects(long, long[], LongRef)
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     * @deprecated use {@link CEi#FindObjects(long, int)} instead
     */
    @Deprecated
    public static long[] FindObjects(long session, int maxObjects) {
        return NCE.FindObjects(C.NATIVE, session, maxObjects);
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @see C#FindObjectsFinal(long)
     * @see NativeProvider#C_FindObjectsFinal(long)
     * @deprecated use {@link CEi#FindObjectsFinal(long)} instead
     */
    @Deprecated
    public static void FindObjectsFinal(long session) {
        NCE.FindObjectsFinal(C.NATIVE, session);
    }

    /**
     * Single-part search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     * @deprecated use {@link CEi#FindObjects(long, CKA...)} instead
     */
    @Deprecated
    public static long[] FindObjects(long session, CKA... templ) {
        return NCE.FindObjects(C.NATIVE, session, templ);
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see C#EncryptInit(long, CKM, long)
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     * @deprecated use {@link CEi#EncryptInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void EncryptInit(long session, CKM mechanism, long key) {
        NCE.EncryptInit(C.NATIVE, session, mechanism, key);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Encrypt(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        NCE.Encrypt(C.NATIVE, session, data, encryptedData, encryptedDataLen);
    }

    /**
     * Encrypts single-part data with 2 calls.  First call determines
     * size of result which may include padding, second call does encrypt.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#EncryptPad(long, byte[])} instead
     */
    @Deprecated
    public static byte[] EncryptPad(long session, byte[] data) {
        return NCE.EncryptPad(C.NATIVE, session, data);
    }

    /**
     * Encrypts single-part data with single call assuming result
     * has no padding and is same size as input.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Encrypt(long, byte[])} instead
     */
    @Deprecated
    public static byte[] Encrypt(long session, byte[] data) {
        return NCE.Encrypt(C.NATIVE, session, data);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @see C#EncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#EncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.EncryptUpdate(C.NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#EncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#EncryptUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] EncryptUpdate(long session, byte[] part) {
        return NCE.EncryptUpdate(C.NATIVE, session, part);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#EncryptFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static void EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        NCE.EncryptFinal(C.NATIVE, session, lastEncryptedPart, lastEncryptedPartLen);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#EncryptFinal(long)} instead
     */
    @Deprecated
    public static byte[] EncryptFinal(long session) {
        return NCE.EncryptFinal(C.NATIVE, session);
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
     * @deprecated use {@link CEi#EncryptPad(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] EncryptPad(long session, CKM mechanism, long key, byte[] data) {
        return NCE.EncryptPad(C.NATIVE, session, mechanism, key, data);
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
     * @deprecated use {@link CEi#Encrypt(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] Encrypt(long session, CKM mechanism, long key, byte[] data) {
        return NCE.Encrypt(C.NATIVE, session, mechanism, key, data);
    }

    /**
     * Initialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see C#DecryptInit(long, CKM, long)
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     * @deprecated use {@link CEi#DecryptInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void DecryptInit(long session, CKM mechanism, long key) {
        NCE.DecryptInit(C.NATIVE, session, mechanism, key);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Decrypt(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        NCE.Decrypt(C.NATIVE, session, encryptedData, data, dataLen);
    }

    /**
     * Decrypts encrypted data in a single-part with 2 calls.  First call determines
     * size of result which may have padding removed, second call does decrypt.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptPad(long, byte[])} instead
     */
    @Deprecated
    public static byte[] DecryptPad(long session, byte[] encryptedData) {
        return NCE.DecryptPad(C.NATIVE, session, encryptedData);
    }

    /**
     * Decrypts encrypted data in a single-part with 1 single call
     * assuming result is not larger than input.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Decrypt(long, byte[])} instead
     */
    @Deprecated
    public static byte[] Decrypt(long session, byte[] encryptedData) {
        return NCE.Decrypt(C.NATIVE, session, encryptedData);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @see C#DecryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        NCE.DecryptUpdate(C.NATIVE, session, encryptedPart, data, dataLen);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see C#DecryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] DecryptUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptUpdate(C.NATIVE, session, encryptedPart);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static void DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        NCE.DecryptFinal(C.NATIVE, session, lastPart, lastPartLen);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestFinal(long)} instead
     */
    @Deprecated
    public static byte[] DecryptFinal(long session) {
        return NCE.DecryptFinal(C.NATIVE, session);
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
     * @deprecated use {@link CEi#DecryptPad(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] DecryptPad(long session, CKM mechanism, long key, byte[] encryptedData) {
        return NCE.DecryptPad(C.NATIVE, session, mechanism, key, encryptedData);
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
     * @deprecated use {@link CEi#Decrypt(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] Decrypt(long session, CKM mechanism, long key, byte[] encryptedData) {
        return NCE.Decrypt(C.NATIVE, session, mechanism, key, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see C#DigestInit(long, CKM)
     * @see NativeProvider#C_DigestInit(long, CKM)
     * @deprecated use {@link CEi#DigestInit(long, CKM)} instead
     */
    @Deprecated
    public static void DigestInit(long session, CKM mechanism) {
        NCE.DigestInit(C.NATIVE, session, mechanism);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Digest(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        NCE.Digest(C.NATIVE, session, data, digest, digestLen);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Digest(long, byte[])} instead
     */
    @Deprecated
    public static byte[] Digest(long session, byte[] data) {
        return NCE.Digest(C.NATIVE, session, data);
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see C#DigestUpdate(long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     * @deprecated use {@link CEi#DigestUpdate(long, byte[])} instead
     */
    @Deprecated
    public static void DigestUpdate(long session, byte[] part) {
        NCE.DigestUpdate(C.NATIVE, session, part);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see C#DigestKey(long, long)
     * @see NativeProvider#C_DigestKey(long, long)
     * @deprecated use {@link CEi#DigestKey(long, long)} instead
     */
    @Deprecated
    public static void DigestKey(long session, long key) {
        NCE.DigestKey(C.NATIVE, session, key);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static void DigestFinal(long session, byte[] digest, LongRef digestLen) {
        NCE.DigestFinal(C.NATIVE, session, digest, digestLen);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestFinal(long)} instead
     */
    @Deprecated
    public static byte[] DigestFinal(long session) {
        return NCE.DigestFinal(C.NATIVE, session);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @param data data to be digested
     * @return digest
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Digest(long, CKM, byte[])} instead
     */
    @Deprecated
    public static byte[] Digest(long session, CKM mechanism, byte[] data) {
        return NCE.Digest(C.NATIVE, session, mechanism, data);
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
     * @deprecated use {@link CEi#SignInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void SignInit(long session, CKM mechanism, long key) {
        NCE.SignInit(C.NATIVE, session, mechanism, key);
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
     * @deprecated use {@link CEi#Sign(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        NCE.Sign(C.NATIVE, session, data, signature, signatureLen);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#Sign(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#Sign(long, byte[])} instead
     */
    @Deprecated
    public static byte[] Sign(long session, byte[] data) {
        return NCE.Sign(C.NATIVE, session, data);
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @see C#SignUpdate(long, byte[])
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     * @deprecated use {@link CEi#SignUpdate(long, byte[])} instead
     */
    @Deprecated
    public static void SignUpdate(long session, byte[] part) {
        NCE.SignUpdate(C.NATIVE, session, part);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#SignFinal(long, byte[], LongRef)} instead
     */
    @Deprecated
    public static void SignFinal(long session, byte[] signature, LongRef signatureLen) {
        NCE.SignFinal(C.NATIVE, session, signature, signatureLen);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     * @deprecated use {@link CEi#SignFinal(long)} instead
     */
    @Deprecated
    public static byte[] SignFinal(long session) {
        return NCE.SignFinal(C.NATIVE, session);
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
     * @deprecated use {@link CEi#Sign(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] Sign(long session, CKM mechanism, long key, byte[] data) {
        return NCE.Sign(C.NATIVE, session, mechanism, key, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see C#SignRecoverInit(long, CKM, long)
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     * @deprecated use {@link CEi#SignRecoverInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void SignRecoverInit(long session, CKM mechanism, long key) {
        NCE.SignRecoverInit(C.NATIVE, session, mechanism, key);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#SignRecover(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        NCE.SignRecover(C.NATIVE, session, data, signature, signatureLen);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#SignRecover(long, byte[])} instead
     */
    @Deprecated
    public static byte[] SignRecover(long session, byte[] data) {
        return NCE.SignRecover(C.NATIVE, session, data);
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
     * @deprecated use {@link CEi#SignRecover(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] SignRecover(long session, CKM mechanism, long key, byte[] data) {
        return NCE.SignRecover(C.NATIVE, session, mechanism, key, data);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyInit(long, CKM, long)
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     * @deprecated use {@link CEi#VerifyInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void VerifyInit(long session, CKM mechanism, long key) {
        NCE.VerifyInit(C.NATIVE, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @see C#Verify(long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     * @deprecated use {@link CEi#Verify(long, byte[], byte[])} instead
     */
    @Deprecated
    public static void Verify(long session, byte[] data, byte[] signature) {
        NCE.Verify(C.NATIVE, session, data, signature);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see C#VerifyUpdate(long, byte[])
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     * @deprecated use {@link CEi#VerifyUpdate(long, byte[])} instead
     */
    @Deprecated
    public static void VerifyUpdate(long session, byte[] part) {
        NCE.VerifyUpdate(C.NATIVE, session, part);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see C#VerifyFinal(long, byte[])
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     * @deprecated use {@link CEi#VerifyFinal(long, byte[])} instead
     */
    @Deprecated
    public static void VerifyFinal(long session, byte[] signature) {
        NCE.VerifyFinal(C.NATIVE, session, signature);
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
     * @deprecated use {@link CEi#Verify(long, CKM, long, byte[], byte[])} instead
     */
    @Deprecated
    public static void Verify(long session, CKM mechanism, long key, byte[] data, byte[] signature) {
        NCE.Verify(C.NATIVE, session, mechanism, key, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyRecoverInit(long, CKM, long)
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     * @deprecated use {@link CEi#VerifyRecoverInit(long, CKM, long)} instead
     */
    @Deprecated
    public static void VerifyRecoverInit(long session, CKM mechanism, long key) {
        NCE.VerifyRecoverInit(C.NATIVE, session, mechanism, key);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#VerifyRecover(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        NCE.VerifyRecover(C.NATIVE, session, signature, data, dataLen);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#VerifyRecover(long, byte[])} instead
     */
    @Deprecated
    public static byte[] VerifyRecover(long session, byte[] signature) {
        return NCE.VerifyRecover(C.NATIVE, session, signature);
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
     * @deprecated use {@link CEi#VerifyRecover(long, CKM, long, byte[])} instead
     */
    @Deprecated
    public static byte[] VerifyRecover(long session, CKM mechanism, long key, byte[] signature) {
        return NCE.VerifyRecover(C.NATIVE, session, mechanism, key, signature);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @see C#DigestEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestEncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.DigestEncryptUpdate(C.NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#DigestEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DigestEncryptUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] DigestEncryptUpdate(long session, byte[] part) {
        return NCE.DigestEncryptUpdate(C.NATIVE, session, part);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @see C#DigestUpdate(long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     * @deprecated use {@link CEi#DecryptDigestUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        NCE.DecryptDigestUpdate(C.NATIVE, session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptDigestUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptDigestUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] DecryptDigestUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptDigestUpdate(C.NATIVE, session, encryptedPart);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @see C#SignEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#SignEncryptUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        NCE.SignEncryptUpdate(C.NATIVE, session, part, encryptedPart, encryptedPartLen);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#SignEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#SignEncryptUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] SignEncryptUpdate(long session, byte[] part) {
        return NCE.SignEncryptUpdate(C.NATIVE, session, part);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @see C#DecryptVerifyUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptVerifyUpdate(long, byte[], byte[], LongRef)} instead
     */
    @Deprecated
    public static void DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        NCE.DecryptVerifyUpdate(C.NATIVE, session, encryptedPart, part, partLen);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptVerifyUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     * @deprecated use {@link CEi#DecryptVerifyUpdate(long, byte[])} instead
     */
    @Deprecated
    public static byte[] DecryptVerifyUpdate(long session, byte[] encryptedPart) {
        return NCE.DecryptVerifyUpdate(C.NATIVE, session, encryptedPart);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @see C#GenerateKey(long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     * @deprecated use {@link CEi#GenerateKey(long, CKM, CKA[], LongRef)} instead
     */
    @Deprecated
    public static void GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        NCE.GenerateKey(C.NATIVE, session, mechanism, templ, key);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @return key handle
     * @see C#GenerateKey(long, CKM, CKA[], LongRef)
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     * @deprecated use {@link CEi#GenerateKey(long, CKM, CKA...)} instead
     */
    @Deprecated
    public static long GenerateKey(long session, CKM mechanism, CKA... templ) {
        return NCE.GenerateKey(C.NATIVE, session, mechanism, templ);
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
     * @deprecated use {@link CEi#GenerateKeyPair(long, CKM, CKA[], CKA[], LongRef, LongRef)} instead
     */
    @Deprecated
    public static void GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate,
                                       LongRef publicKey, LongRef privateKey) {
        NCE.GenerateKeyPair(C.NATIVE, session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
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
     * @deprecated use {@link CEi#WrapKey(long, CKM, long, long, byte[], LongRef)} instead
     */
    @Deprecated
    public static void WrapKey(long session, CKM mechanism, long wrappingKey, long key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        NCE.WrapKey(C.NATIVE, session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
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
     * @deprecated use {@link CEi#WrapKey(long, CKM, long, long)} K} instead
     */
    @Deprecated
    public static byte[] WrapKey(long session, CKM mechanism, long wrappingKey, long key) {
        return NCE.WrapKey(C.NATIVE, session, mechanism, wrappingKey, key);
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
     * @deprecated use {@link CEi#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)} instead
     */
    @Deprecated
    public static void UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        NCE.UnwrapKey(C.NATIVE, session, mechanism, unwrappingKey, wrappedKey, templ, key);
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
     * @deprecated use {@link CEi#UnwrapKey(long, CKM, long, byte[], CKA...)} instead
     */
    @Deprecated
    public static long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        return NCE.UnwrapKey(C.NATIVE, session, mechanism, unwrappingKey, wrappedKey, templ);
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
     * @deprecated use {@link CEi#DeriveKey(long, CKM, long, CKA[], LongRef)} instead
     */
    @Deprecated
    public static void DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        NCE.DeriveKey(C.NATIVE, session, mechanism, baseKey, templ, key);
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
     * @deprecated use {@link CEi#DeriveKey(long, CKM, long, CKA...)} instead
     */
    @Deprecated
    public static long DeriveKey(long session, CKM mechanism, long baseKey, CKA... templ) {
        return NCE.DeriveKey(C.NATIVE, session, mechanism, baseKey, templ);
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see C#SeedRandom(long, byte[])
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     * @deprecated use {@link CEi#SeedRandom(long, byte[])} instead
     */
    @Deprecated
    public static void SeedRandom(long session, byte[] seed) {
        NCE.SeedRandom(C.NATIVE, session, seed);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     * @deprecated use {@link CEi#GenerateRandom(long, byte[])} instead
     */
    @Deprecated
    public static void GenerateRandom(long session, byte[] randomData) {
        NCE.GenerateRandom(C.NATIVE, session, randomData);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     * @deprecated use {@link CEi#GenerateRandom(long, int)} instead
     */
    @Deprecated
    public static byte[] GenerateRandom(long session, int randomLen) {
        return NCE.GenerateRandom(C.NATIVE, session, randomLen);
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     * @deprecated use {@link CEi#GetFunctionStatus(long)} instead
     */
    @Deprecated
    public static void GetFunctionStatus(long session) {
        NCE.GetFunctionStatus(C.NATIVE, session);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     * @deprecated use {@link CEi#CancelFunction(long)} instead
     */
    @Deprecated
    public static void CancelFunction(long session) {
        NCE.CancelFunction(C.NATIVE, session);
    }
}
