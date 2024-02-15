/*
 * Copyright 2021 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
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
 * <p>
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
public class CryptokiE {

    /**
     * Underlying Cryptoki object.
     */
    private final Cryptoki c;

    /**
     * Strategy for determining the length of attributes in a GetAttribute process.
     * <p>
     * Default: {@link AttributeLengthStrategy.IndefiniteLengthStrategy}
     *
     * @see AttributeLengthStrategy.MaxLengthStrategy
     * @see AttributeLengthStrategy.IndefiniteLengthStrategy
     */
    private AttributeLengthStrategy attributeLengthStrategy = new AttributeLengthStrategy.IndefiniteLengthStrategy();

    /**
     * Flag enabling batch mode for getting attributes.
     * If <code>true</code>, then all attributes are retrieved in a single call to
     * <code>C_GetAttributeValue</code>.  If <code>false</code>, then each attribute is
     * retrieved in a separate call to <code>C_GetAttributeValue</code>.
     * <p>
     * Default: true
     */
    private boolean attributeBatchModeEnabled = true;

    public CryptokiE() {
      this.c = new Cryptoki();
    }

    /**
     * @param c Cryptoki object to wrap.
     */
    public CryptokiE(Cryptoki c) {
      this.c = c;
    }

    /**
     * Initialize cryptoki.
     * @see C#Initialize()
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     */
    public void Initialize() {
        long rv = c.Initialize();
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see C#Finalize()
     * @see NativeProvider#C_Finalize(NativePointer)
     */
    public void Finalize() {
        long rv = c.Finalize();
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public void GetInfo(CK_INFO info) {
        long rv = c.GetInfo(info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Returns general information about Cryptoki.
     * @return info
     * @see C#GetInfo(CK_INFO)
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public CK_INFO GetInfo() {
        CK_INFO info = new CK_INFO();
        GetInfo(info);
        return info;
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public void GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        long rv = c.GetSlotList(tokenPresent, slotList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see C#GetSlotList(boolean, long[], LongRef)
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef)
     */
    public long[] GetSlotList(boolean tokenPresent) {
        LongRef count = new LongRef();
        GetSlotList(tokenPresent, null, count);
        long[] result = new long[(int) count.value()];
        GetSlotList(tokenPresent, result, count);
        return result;
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
    public long GetSlot(String label) {
        long[] allslots = GetSlotList(true);
        for (long slot : allslots) {
            CK_TOKEN_INFO tok = GetTokenInfo(slot);
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
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public void GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        long rv = c.GetSlotInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see C#GetSlotInfo(long, CK_SLOT_INFO)
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public CK_SLOT_INFO GetSlotInfo(long slotID) {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        GetSlotInfo(slotID, info);
        return info;
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public void GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        long rv = c.GetTokenInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see C#GetTokenInfo(long, CK_TOKEN_INFO)
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public CK_TOKEN_INFO GetTokenInfo(long slotID) {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        GetTokenInfo(slotID, info);
        return info;
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param pReserved reserved.  Should be null
     * @see C#WaitForSlotEvent(long, LongRef, NativePointer)
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    public void WaitForSlotEvent(long flags, LongRef slot, NativePointer pReserved) {
        long rv = c.WaitForSlotEvent(flags, slot, pReserved);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public void GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        long rv = c.GetMechanismList(slotID, mechanismList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see C#GetMechanismList(long, long[], LongRef)
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public long[] GetMechanismList(long slotID) {
        LongRef count = new LongRef();
        GetMechanismList(slotID, null, count);
        long[] mechanisms = new long[(int) count.value()];
        GetMechanismList(slotID, mechanisms, count);
        return mechanisms;
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public void GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        long rv = c.GetMechanismInfo(slotID, type, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see C#GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public CK_MECHANISM_INFO GetMechanismInfo(long slotID, long type) {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        GetMechanismInfo(slotID, type, info);
        return info;
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
    public void InitToken(long slotID, byte[] pin, byte[] label) {
        long rv = c.InitToken(slotID, pin, label);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#InitPIN(long, byte[])
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    public void InitPIN(long session, byte[] pin) {
        long rv = c.InitPIN(session, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see C#SetPIN(long, byte[], byte[])
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    public void SetPIN(long session, byte[] oldPin, byte[] newPin) {
        long rv = c.SetPIN(session, oldPin, newPin);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        long rv = c.OpenSession(slotID, flags, application, notify, session);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        LongRef session = new LongRef();
        OpenSession(slotID, flags, application, notify, session);
        return session.value();
    }

    /**
     * Opens a session between an application and a token using {@link CK_SESSION_INFO#CKF_RW_SESSION and CK_SESSION_INFO#CKF_SERIAL_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see C#OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public long OpenSession(long slotID) {
        return OpenSession(slotID, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see C#CloseSession(long)
     * @see NativeProvider#C_CloseSession(long)
     */
    public void CloseSession(long session) {
        long rv = c.CloseSession(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see C#CloseAllSessions(long)
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public void CloseAllSessions(long slotID) {
        long rv = c.CloseAllSessions(slotID);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public void GetSessionInfo(long session, CK_SESSION_INFO info) {
        long rv = c.GetSessionInfo(session, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see C#GetSessionInfo(long, CK_SESSION_INFO)
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public CK_SESSION_INFO GetSessionInfo(long session) {
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        GetSessionInfo(session, info);
        return info;
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public void GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        long rv = c.GetOperationState(session, operationState, operationStateLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see C#GetOperationState(long, byte[], LongRef)
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public byte[] GetOperationState(long session) {
        LongRef len = new LongRef();
        GetOperationState(session, null, len);
        byte[] result = new byte[(int) len.value()];
        GetOperationState(session, result, len);
        return resize(result, (int) len.value());
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
    public void SetOperationState(long session, byte[] operationState, long encryptionKey, long authenticationKey) {
        long rv = c.SetOperationState(session, operationState, encryptionKey, authenticationKey);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Logs a user into a token.  Ignores CKR=0x00000100: USER_ALREADY_LOGGED_IN
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void Login(long session, long userType, byte[] pin) {
        long rv = c.Login(session, userType, pin);
        if (rv != CKR.OK && rv != CKR.USER_ALREADY_LOGGED_IN) throw new CKRException(rv);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginUser(long session, byte[] pin) {
        Login(session, CKU.USER, pin);
    }

    /**
     * Los a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginUser(long session, String pin) {
        LoginUser(session, Buf.c2b(pin));
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginSO(long session, byte[] pin) {
        Login(session, CKU.SO, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN encoded in a single byte encoding format such as ISO8859-1
     * @see C#Login(long, long, byte[])
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public void LoginSO(long session, String pin) {
        LoginSO(session, Buf.c2b(pin));
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see C#Logout(long)
     * @see NativeProvider#C_Logout(long)
     */
    public void Logout(long session) {
        long rv = c.Logout(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public void CreateObject(long session, CKA[] templ, LongRef object) {
        long rv = c.CreateObject(session, templ, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see C#CreateObject(long, CKA[], LongRef)
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public long CreateObject(long session, CKA... templ) {
        LongRef object = new LongRef();
        CreateObject(session, templ, object);
        return object.value();
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
    public void CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        long rv = c.CopyObject(session, object, templ, newObject);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public long CopyObject(long session, long object, CKA... templ) {
        LongRef newObject = new LongRef();
        CopyObject(session, object, templ, newObject);
        return newObject.value();
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see C#DestroyObject(long, long)
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    public void DestroyObject(long session, long object) {
        long rv = c.DestroyObject(session, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public void GetObjectSize(long session, long object, LongRef size) {
        long rv = c.GetObjectSize(session, object, size);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see C#GetObjectSize(long, long, LongRef)
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public long GetObjectSize(long session, long object) {
        LongRef size = new LongRef();
        GetObjectSize(session, object, size);
        return size.value();
    }

    /**
     * Obtains the value of one or more object attributes, or the lengths needed to be allocated in order to retrieve the values.
     * See PKCS#11 v2.40 section 5.7, C_GetAttributeValue.
     *   3. Otherwise, if the pValue field has the value NULL_PTR, then the ulValueLen field is modified to hold the exact length of the specified attribute for the object
     *   
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, if length of templ[i].uLvalueLen is 0 it will be set to the length of the value needed, 
     * if templ[i].pValue is allocated with the correct length to hold the value the value is filled into templ[i].pValue
     * @see #GetAttributeValue(long, long, long...)
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public void GetAttributeValue(long session, long object, CKA... templ) {
        if (templ == null || templ.length == 0) {
            return;
        }
        long rv = c.GetAttributeValue(session, object, templ);
        // PKCS#11 v2.40, section 5.7, C_GetAttributeValue
        //  Note that the error codes CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL 
        //  do not denote true errors for C_GetAttributeValue.  If a call to C_GetAttributeValue returns any of these 
        //  three values, then the call MUST nonetheless have processed every attribute in the template supplied to 
        //  C_GetAttributeValue.  Each attribute in the template whose value can be returned by the call to 
        //  C_GetAttributeValue will be returned by the call to C_GetAttributeValue.
        // So we will assume that values are processed and returned, perhaps as 0 length, null values (CK_UNAVAILABLE_INFORMATION)
        // Unless CKR_BUFFER_TOO_SMALL that actually is something the caller must fix and the caller should be notified
        if (rv != CKR.OK && rv != CKR.ATTRIBUTE_SENSITIVE && rv != CKR.ATTRIBUTE_TYPE_INVALID) {
            throw new CKRException(rv);
        }
    }

    /**
     * Obtains the value of one attributes, or returns CKA with null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see C#GetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public CKA GetAttributeValue(long session, long object, long cka) {
        // the general fetching process optimizes single fetch as well
        return GetAttributeValue(session, object, new long[] { cka })[0];
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
    public CKA[] GetAttributeValue(long session, long object, long... types) {
        if (types == null || types.length == 0) {
            return new CKA[0];
        }

        return new GetAttributeProcess(c, session, object, attributeLengthStrategy, attributeBatchModeEnabled, types).fetch();
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attributes and values
     * @see C#SetAttributeValue(long, long, CKA[])
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    public void SetAttributeValue(long session, long object, CKA... templ) {
        long rv = c.SetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initailses a search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public void FindObjectsInit(long session, CKA... templ) {
        long rv = c.FindObjectsInit(session, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void FindObjects(long session, long[] found, LongRef objectCount) {
        long rv = c.FindObjects(session, found, objectCount);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public long[] FindObjects(long session, int maxObjects) {
        long[] found = new long[maxObjects];
        LongRef len = new LongRef();
        FindObjects(session, found, len);
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
     * @see C#FindObjectsFinal(long)
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public void FindObjectsFinal(long session) {
        long rv = c.FindObjectsFinal(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Single-part search for token and session objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see C#FindObjectsInit(long, CKA[])
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public long[] FindObjects(long session, CKA... templ) {
        // According to https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323205460:
        // "After calling C_FindObjectsInit, the application may call
        // C_FindObjects one or more times to obtain handles for objects
        // matching the template, and then eventually call
        // C_FindObjectsFinal to finish the active search operation."
        FindObjectsInit(session, templ);
        boolean success = false;
        try {
            int maxObjects = 1024;
            // call once
            long[] result = FindObjects(session, maxObjects);
            // most likely we are done now
            if (result.length < maxObjects) {
                success = true;
                return result;
            }

            // this is a lot of objects! try to find in batches of 1024 more, adding to result as we go
            while (true) {
                long[] found = FindObjects(session, maxObjects);
                long[] temp = new long[result.length + found.length];
                System.arraycopy(result, 0, temp, 0, result.length);
                System.arraycopy(found, 0, temp, result.length, found.length);
                result = temp;
                if (found.length < maxObjects) { // exhausted, didn't find 1024 more
                    success = true;
                    return result;
                }
            }
        } finally {
            try {
                // Must be called even if there is an error, otherwise the
                // session will remain in the FindObjects state and not
                // allow any other operations.
                FindObjectsFinal(session);
            } catch (RuntimeException e) {
                if (success) { // Don't throw another exception on error
                    throw e;
                }
            }
        }
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see C#EncryptInit(long, CKM, long)
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    public void EncryptInit(long session, CKM mechanism, long key) {
        long rv = c.EncryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        long rv = c.Encrypt(session, data, encryptedData, encryptedDataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public byte[] EncryptPad(long session, byte[] data) {
        LongRef l = new LongRef();
        Encrypt(session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Encrypt(session, data, result, l);
        return resize(result, (int) l.value());
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
    public byte[] Encrypt(long session, byte[] data) {
        byte[] result = new byte[data.length];
        LongRef l = new LongRef(result.length);
        Encrypt(session, data, result, l);
        return resize(result, (int) l.value);
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
    public void EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = c.EncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#EncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] EncryptUpdate(long session, byte[] part) {
        LongRef l = new LongRef();
        EncryptUpdate(session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        EncryptUpdate(session, part, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public void EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        long rv = c.EncryptFinal(session, lastEncryptedPart, lastEncryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see C#EncryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public byte[] EncryptFinal(long session) {
        LongRef l = new LongRef();
        EncryptFinal(session, null, l);
        byte[] result = new byte[(int) l.value()];
        EncryptFinal(session, result, l);
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
     * @see C#Encrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] EncryptPad(long session, CKM mechanism, long key, byte[] data) {
        EncryptInit(session, mechanism, key);
        return EncryptPad(session, data);
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
    public byte[] Encrypt(long session, CKM mechanism, long key, byte[] data) {
        EncryptInit(session, mechanism, key);
        return Encrypt(session, data);
    }

    /**
     * Initialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see C#DecryptInit(long, CKM, long)
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    public void DecryptInit(long session, CKM mechanism, long key) {
        long rv = c.DecryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        long rv = c.Decrypt(session, encryptedData, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);

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
    public byte[] DecryptPad(long session, byte[] encryptedData) {
        LongRef l = new LongRef();
        Decrypt(session, encryptedData, null, l);
        byte[] result = new byte[(int) l.value()];
        Decrypt(session, encryptedData, result, l);
        return resize(result, (int) l.value());
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
    public byte[] Decrypt(long session, byte[] encryptedData) {
        byte[] result = new byte[encryptedData.length];
        LongRef l = new LongRef(result.length);
        Decrypt(session, encryptedData, result, l);
        return resize(result, (int) l.value());
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
    public void DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        long rv = c.DecryptUpdate(session, encryptedPart, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see C#DecryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptUpdate(long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptUpdate(session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptUpdate(session, encryptedPart, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public void DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        long rv = c.DecryptFinal(session, lastPart, lastPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see C#DecryptFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public byte[] DecryptFinal(long session) {
        LongRef l = new LongRef();
        DecryptFinal(session, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptFinal(session, result, l);
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
     * @see C#Decrypt(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptPad(long session, CKM mechanism, long key, byte[] encryptedData) {
        DecryptInit(session, mechanism, key);
        return DecryptPad(session, encryptedData);
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
    public byte[] Decrypt(long session, CKM mechanism, long key, byte[] encryptedData) {
        DecryptInit(session, mechanism, key);
        return Decrypt(session, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see C#DigestInit(long, CKM)
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    public void DigestInit(long session, CKM mechanism) {
        long rv = c.DigestInit(session, mechanism);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        long rv = c.Digest(session, data, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see C#Digest(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public byte[] Digest(long session, byte[] data) {
        LongRef l = new LongRef();
        Digest(session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Digest(session, data, result, l);
        return resize(result, (int) l.value());
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see C#DigestUpdate(long, byte[])
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public void DigestUpdate(long session, byte[] part) {
        long rv = c.DigestUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see C#DigestKey(long, long)
     * @see NativeProvider#C_DigestKey(long, long)
     */
    public void DigestKey(long session, long key) {
        long rv = c.DigestKey(session, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public void DigestFinal(long session, byte[] digest, LongRef digestLen) {
        long rv = c.DigestFinal(session, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see C#DigestFinal(long, byte[], LongRef)
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public byte[] DigestFinal(long session) {
        LongRef l = new LongRef();
        DigestFinal(session, null, l);
        byte[] result = new byte[(int) l.value()];
        DigestFinal(session, result, l);
        return resize(result, (int) l.value());
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
    public byte[] Digest(long session, CKM mechanism, byte[] data) {
        DigestInit(session, mechanism);
        return Digest(session, data);
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
    public void SignInit(long session, CKM mechanism, long key) {
        long rv = c.SignInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        long rv = c.Sign(session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public byte[] Sign(long session, byte[] data) {
        LongRef l = new LongRef();
        Sign(session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        Sign(session, data, result, l);
        return resize(result, (int) l.value());
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
    public void SignUpdate(long session, byte[] part) {
        long rv = c.SignUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public void SignFinal(long session, byte[] signature, LongRef signatureLen) {
        long rv = c.SignFinal(session, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see C#SignFinal(long, byte[], LongRef)
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public byte[] SignFinal(long session) {
        LongRef l = new LongRef();
        SignFinal(session, null, l);
        byte[] result = new byte[(int) l.value()];
        SignFinal(session, result, l);
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
     * @see C#Sign(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public byte[] Sign(long session, CKM mechanism, long key, byte[] data) {
        SignInit(session, mechanism, key);
        return Sign(session, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see C#SignRecoverInit(long, CKM, long)
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    public void SignRecoverInit(long session, CKM mechanism, long key) {
        long rv = c.SignRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        long rv = c.SignRecover(session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] SignRecover(long session, byte[] data) {
        LongRef l = new LongRef();
        SignRecover(session, data, null, l);
        byte[] result = new byte[(int) l.value()];
        SignRecover(session, data, result, l);
        return resize(result, (int) l.value());
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
    public byte[] SignRecover(long session, CKM mechanism, long key, byte[] data) {
        SignRecoverInit(session, mechanism, key);
        return SignRecover(session, data);
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
    public void VerifyInit(long session, CKM mechanism, long key) {
        long rv = c.VerifyInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void Verify(long session, byte[] data, byte[] signature) {
        long rv = c.Verify(session, data, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see C#VerifyUpdate(long, byte[])
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    public void VerifyUpdate(long session, byte[] part) {
        long rv = c.VerifyUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see C#VerifyFinal(long, byte[])
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    public void VerifyFinal(long session, byte[] signature) {
        long rv = c.VerifyFinal(session, signature);
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
     * @see C#Verify(long, byte[], byte[])
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public void Verify(long session, CKM mechanism, long key, byte[] data, byte[] signature) {
        VerifyInit(session, mechanism, key);
        Verify(session, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyRecoverInit(long, CKM, long)
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    public void VerifyRecoverInit(long session, CKM mechanism, long key) {
        long rv = c.VerifyRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public void VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        long rv = c.VerifyRecover(session, signature, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public byte[] VerifyRecover(long session, byte[] signature) {
        LongRef l = new LongRef();
        VerifyRecover(session, signature, null, l);
        byte[] result = new byte[(int) l.value()];
        VerifyRecover(session, signature, result, l);
        return resize(result, (int) l.value());
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
    public byte[] VerifyRecover(long session, CKM mechanism, long key, byte[] signature) {
        VerifyRecoverInit(session, mechanism, key);
        return VerifyRecover(session, signature);
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
    public void DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = c.DigestEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#DigestEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DigestEncryptUpdate(long session, byte[] part) {
        LongRef l = new LongRef();
        DigestEncryptUpdate(session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        DigestEncryptUpdate(session, part, result, l);
        return resize(result, (int) l.value());
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
    public void DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        long rv = c.DecryptDigestUpdate(session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptDigestUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptDigestUpdate(long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptDigestUpdate(session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptDigestUpdate(session, encryptedPart, result, l);
        return resize(result, (int) l.value());
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
    public void SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        long rv = c.SignEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#SignEncryptUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] SignEncryptUpdate(long session, byte[] part) {
        LongRef l = new LongRef();
        SignEncryptUpdate(session, part, null, l);
        byte[] result = new byte[(int) l.value()];
        SignEncryptUpdate(session, part, result, l);
        return resize(result, (int) l.value());
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
    public void DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        long rv = c.DecryptVerifyUpdate(session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptVerifyUpdate(long, byte[], byte[], LongRef)
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public byte[] DecryptVerifyUpdate(long session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptVerifyUpdate(session, encryptedPart, null, l);
        byte[] result = new byte[(int) l.value()];
        DecryptVerifyUpdate(session, encryptedPart, result, l);
        return resize(result, (int) l.value());
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
    public void GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        long rv = c.GenerateKey(session, mechanism, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public long GenerateKey(long session, CKM mechanism, CKA... templ) {
        LongRef key = new LongRef();
        GenerateKey(session, mechanism, templ, key);
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
     * @see C#GenerateKeyPair(long, CKM, CKA[], CKA[], LongRef, LongRef)
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, CKA[], long, CKA[], long, LongRef, LongRef)
     */
    public void GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate,
            LongRef publicKey, LongRef privateKey) {
        long rv = c.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
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
     * @see C#WrapKey(long, CKM, long, long, byte[], LongRef)
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public void WrapKey(long session, CKM mechanism, long wrappingKey, long key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        long rv = c.WrapKey(session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public byte[] WrapKey(long session, CKM mechanism, long wrappingKey, long key) {
        LongRef l = new LongRef();
        WrapKey(session, mechanism, wrappingKey, key, null, l);
        byte[] result = new byte[(int) l.value()];
        WrapKey(session, mechanism, wrappingKey, key, result, l);
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
     * @see C#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public void UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        long rv = c.UnwrapKey(session, mechanism, unwrappingKey, wrappedKey, templ, key);
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
     * @see C#UnwrapKey(long, CKM, long, byte[], CKA[], LongRef)
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        LongRef result = new LongRef();
        UnwrapKey(session, mechanism, unwrappingKey, wrappedKey, templ, result);
        return result.value();
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
    public void DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        long rv = c.DeriveKey(session, mechanism, baseKey, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
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
    public long DeriveKey(long session, CKM mechanism, long baseKey, CKA... templ) {
        LongRef key = new LongRef();
        DeriveKey(session, mechanism, baseKey, templ, key);
        return key.value();
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see C#SeedRandom(long, byte[])
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    public void SeedRandom(long session, byte[] seed) {
        long rv = c.SeedRandom(session, seed);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public void GenerateRandom(long session, byte[] randomData) {
        long rv = c.GenerateRandom(session, randomData);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see C#GenerateRandom(long, byte[])
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public byte[] GenerateRandom(long session, int randomLen) {
        byte[] result = new byte[randomLen];
        GenerateRandom(session, result);
        return result;
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public void GetFunctionStatus(long session) {
        long rv = c.GetFunctionStatus(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(long)
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public void CancelFunction(long session) {
        long rv = c.CancelFunction(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Resize buf to specified length. If buf already size 'newSize', then return buf, else return resized buf.
     * @param buf buf
     * @param newSize length to resize to
     * @return if buf already size 'newSize', then return buf, else return resized buf
     */
    private byte[] resize(byte[] buf, int newSize) {
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
    public NativeProviderMetrics getMetrics() {
        return c.getMetrics();
    }

    /**
     * Set the strategy to use for getting the length of an attribute.
     *
     * @param attributeLengthStrategy the strategy to use for getting the length of an attribute
     */
    public void setAttributeLengthStrategy(AttributeLengthStrategy attributeLengthStrategy) {
        this.attributeLengthStrategy = attributeLengthStrategy;
    }

    /**
     * Get the strategy to use for getting the length of an attribute.
     *
     * @return the strategy to use for getting the length of an attribute
     */
    public AttributeLengthStrategy getAttributeLengthStrategy() {
        return attributeLengthStrategy;
    }

    /**
     * Set the mode to use for getting attribute values.
     *
     * @param attributeBatchModeEnabled if true, then batch mode is enabled
     */
    public void setAttributeBatchModeEnabled(boolean attributeBatchModeEnabled) {
        this.attributeBatchModeEnabled = attributeBatchModeEnabled;
    }

    /**
     * Get the mode to use for getting attribute values.
     *
     * @return if true, then batch mode is enabled
     */
    public boolean isAttributeBatchModeEnabled() {
        return attributeBatchModeEnabled;
    }
}
