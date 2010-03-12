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

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

/**
 * This is the preferred java interface for calling cryptoki functions.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link Native} provides the lowest level JNA direct mapping to the C_* functions. There is little reason why you
 * would ever want to invoke it directly, but you can.
 * <li>{@link C} provides the exact same interface (although the 'C_' at the start of the function is removed since 'C.'
 * when you call the static methods looks equivalent), but it handles some of the low-level JNA plumbing such as
 * 'pushing' any values changed within the native call back into java objects. You can use this if you require
 * fine-grain control over something.
 * <li>{@link CE} provides the most user-friendly interface. It converts any non-zero return values into a
 * {@link CKRException}, and automatically resizes arrays and other helpful things. I recommend that you use it
 * exclusively if possible.
 * </ol>
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CE {

    /**
     * Initialize cryptoki.
     * @see C#Initialize()
     * @see Native#C_Initialize(CK_C_INITIALIZE_ARGS)
     */
    public static void Initialize() {
        int rv = C.Initialize();
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see C#Finalize()
     * @see Native#C_Finalize(Pointer)
     */
    public static void Finalize() {
        int rv = C.Finalize();
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @see C#GetInfo(CK_INFO)
     * @see Native#C_GetInfo(CK_INFO)
     */
    public static void GetInfo(CK_INFO info) {
        int rv = C.GetInfo(info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @see C#GetSlotList(boolean, int[], LongRef)
     * @see Native#C_GetSlotList(byte, LongArray, LongRef)
     */
    public static void GetSlotList(boolean tokenPresent, int[] slotList, LongRef count) {
        int rv = C.GetSlotList(tokenPresent, slotList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @return slot list
     * @see C#GetSlotList(boolean, int[], LongRef)
     * @see Native#C_GetSlotList(byte, LongArray, LongRef)
     */
    public static int[] GetSlotList(boolean tokenPresent) {
        LongRef count = new LongRef();
        GetSlotList(tokenPresent, null, count);
        int[] result = new int[count.val()];
        GetSlotList(tokenPresent, result, count);
        return result;
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @see C#GetSlotInfo(int, CK_SLOT_INFO)
     * @see Native#C_GetSlotInfo(com.sun.jna.NativeLong, CK_SLOT_INFO)
     */
    public static void GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = C.GetSlotInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @return slot info
     * @see C#GetSlotInfo(int, CK_SLOT_INFO)
     * @see Native#C_GetSlotInfo(com.sun.jna.NativeLong, CK_SLOT_INFO)
     */
    public static CK_SLOT_INFO GetSlotInfo(int slotID) {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        GetSlotInfo(slotID, info);
        return info;
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @see C#GetTokenInfo(int, CK_TOKEN_INFO)
     * @see Native#C_GetTokenInfo(com.sun.jna.NativeLong, CK_TOKEN_INFO)
     */
    public static void GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = C.GetTokenInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @return token info
     * @see C#GetTokenInfo(int, CK_TOKEN_INFO)
     * @see Native#C_GetTokenInfo(com.sun.jna.NativeLong, CK_TOKEN_INFO)
     */
    public static CK_TOKEN_INFO GetTokenInfo(int slotID) {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        GetTokenInfo(slotID, info);
        return info;
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param reserved reserved.  Should be null
     * @see C#WaitForSlotEvent(int, LongRef, Pointer)
     * @see Native#C_WaitForSlotEvent(com.sun.jna.NativeLong, LongRef, Pointer)
     */
    public static void WaitForSlotEvent(int flags, LongRef slot, Pointer pReserved) {
        int rv = C.WaitForSlotEvent(flags, slot, pReserved);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @see C#GetMechanismList(int, int[], LongRef)
     * @see Native#C_GetMechanismList(com.sun.jna.NativeLong, LongArray, LongRef)
     */
    public static void GetMechanismList(int slotID, int[] mechanism_list, LongRef count) {
        int rv = C.GetMechanismList(slotID, mechanism_list, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @return mechanism list (array of {@link CKM})
     * @see C#GetMechanismList(int, int[], LongRef)
     * @see Native#C_GetMechanismList(com.sun.jna.NativeLong, LongArray, LongRef)
     */
    public static int[] GetMechanismList(int slotID) {
        LongRef count = new LongRef();
        GetMechanismList(slotID, null, count);
        int[] mechanisms = new int[count.val()];
        GetMechanismList(slotID, mechanisms, count);
        return mechanisms;
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param info receives mechanism info
     * @see C#GetMechanismInfo(int, int, CK_MECHANISM_INFO)
     * @see Native#C_GetMechanismInfo(com.sun.jna.NativeLong, com.sun.jna.NativeLong, CK_MECHANISM_INFO)
     */
    public static void GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        int rv = C.GetMechanismInfo(slotID, type, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @return mechanism info
     * @see C#GetMechanismInfo(int, int, CK_MECHANISM_INFO)
     * @see Native#C_GetMechanismInfo(com.sun.jna.NativeLong, com.sun.jna.NativeLong, CK_MECHANISM_INFO)
     */
    public static CK_MECHANISM_INFO GetMechanismInfo(int slotID, int type) {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        GetMechanismInfo(slotID, type, info);
        return info;
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's intital PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @see C#InitToken(int, byte[], byte[])
     * @see Native#C_InitToken(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[])
     */
    public static void InitToken(int slotID, byte[] pin, byte[] label) {
        int rv = C.InitToken(slotID, pin, label);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#InitPIN(int, byte[])
     * @see Native#C_InitPIN(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void InitPIN(int session, byte[] pin) {
        int rv = C.InitPIN(session, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @see C#SetPIN(int, byte[], byte[])
     * @see Native#C_SetPIN(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SetPIN(int session, byte[] oldPin, byte[] newPin) {
        int rv = C.SetPIN(session, oldPin, newPin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param session gets session handle
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static void OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        int rv = C.OpenSession(slotID, flags, application, notify, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @return session handle
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify) {
        LongRef session = new LongRef();
        OpenSession(slotID, flags, application, notify, session);
        return session.val();
    }

    /**
     * Opens a session between an application and a token using {@link CKS#RW_PUBLIC_SESSION}
     * and null application and notify.
     * @param slotID the slot's ID
     * @return session handle
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID) {
        return OpenSession(slotID, CKS.RW_PUBLIC_SESSION, null, null);
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @see C#CloseSession(int)
     * @see Native#C_CloseSession(com.sun.jna.NativeLong)
     */
    public static void CloseSession(int session) {
        int rv = C.CloseSession(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @see C#CloseAllSessions(int)
     * @see Native#C_CloseAllSessions(com.sun.jna.NativeLong)
     */
    public static void CloseAllSessions(int slotID) {
        int rv = C.CloseAllSessions(slotID);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @see C#GetSessionInfo(int, CK_SESSION_INFO)
     * @see Native#C_GetSessionInfo(com.sun.jna.NativeLong, CK_SESSION_INFO)
     */
    public static void GetSessionInfo(int session, CK_SESSION_INFO info) {
        int rv = C.GetSessionInfo(session, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @return session info
     * @see C#GetSessionInfo(int, CK_SESSION_INFO)
     * @see Native#C_GetSessionInfo(com.sun.jna.NativeLong, CK_SESSION_INFO)
     */
    public static CK_SESSION_INFO GetSessionInfo(int session) {
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        GetSessionInfo(session);
        return info;
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @see C#GetOperationState(int, byte[], LongRef)
     * @see Native#C_GetOperationState(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void GetOperationState(int session, byte[] operationState, LongRef operationStateLen) {
        int rv = C.GetOperationState(session, operationState, operationStateLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @return operation state
     * @see C#GetOperationState(int, byte[], LongRef)
     * @see Native#C_GetOperationState(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] GetOperationState(int session) {
        LongRef len = new LongRef();
        GetOperationState(session, null, len);
        byte[] result = new byte[len.val()];
        GetOperationState(session, result, len);
        return resize(result, len.val());
    }

    /**
     * Restores the state of the cryptographic operation in a session.
     * @param session the session's handle
     * @param operationState holds state
     * @param encryptionKey en/decryption key
     * @param authenticationKey sign/verify key
     * @see C#SetOperationState(int, byte[], int, int)
     * @see Native#C_SetOperationState(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void SetOperationState(int session, byte[] operationState, int encryptionKey, int authenticationKey) {
        int rv = C.SetOperationState(session, operationState, encryptionKey, authenticationKey);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Logs a user into a token.
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void Login(int session, int userType, byte[] pin) {
        int rv = C.Login(session, userType, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Logs a normal user into a token.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void LoginUser(int session, byte[] pin) {
        Login(session, CKU.USER, pin);
    }

    /**
     * Logs SO into a token.
     * @param session the session's handle
     * @param pin SO PIN
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void LoginSO(int session, byte[] pin) {
        Login(session, CKU.SO, pin);
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @see C#Logout(int)
     * @see Native#C_Logout(com.sun.jna.NativeLong)
     */
    public static void Logout(int session) {
        int rv = C.Logout(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @see C#CreateObject(int, CKA[], LongRef)
     * @see Native#C_CreateObject(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void CreateObject(int session, CKA[] templ, LongRef object) {
        int rv = C.CreateObject(session, templ, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @return new object handle
     * @see C#CreateObject(int, CKA[], LongRef)
     * @see Native#C_CreateObject(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int CreateObject(int session, CKA... templ) {
        LongRef object = new LongRef();
        CreateObject(session, templ, object);
        return object.val();
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @see C#CopyObject(int, int, CKA[], LongRef)
     * @see Native#C_CopyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void CopyObject(int session, int object, CKA[] templ, LongRef newObject) {
        int rv = C.CopyObject(session, object, templ, newObject);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @return new object handle
     * @see C#CopyObject(int, int, CKA[], LongRef)
     * @see Native#C_CopyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int CopyObject(int session, int object, CKA... templ) {
        LongRef newObject = new LongRef();
        CopyObject(session, object, templ, newObject);
        return newObject.val();
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @see C#DestroyObject(int, int)
     * @see Native#C_DestroyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void DestroyObject(int session, int object) {
        int rv = C.DestroyObject(session, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @see C#GetObjectSize(int, int, LongRef)
     * @see Native#C_GetObjectSize(com.sun.jna.NativeLong, com.sun.jna.NativeLong, LongRef)
     */
    public static void GetObjectSize(int session, int object, LongRef size) {
        int rv = C.GetObjectSize(session, object, size);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @return size of object in bytes
     * @see C#GetObjectSize(int, int, LongRef)
     * @see Native#C_GetObjectSize(com.sun.jna.NativeLong, com.sun.jna.NativeLong, LongRef)
     */
    public static int GetObjectSize(int session, int object) {
        LongRef size = new LongRef();
        GetObjectSize(session, object, size);
        return size.val();
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void GetAttributeValue(int session, int object, CKA... templ) {
        if (templ == null || templ.length == 0) {
            return;
        }
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Obtains the value of one attributes, or returns CKA will null value if attribute doesn't exist.
     * @param session the session's handle
     * @param object the objects's handle
     * @param cka {@link CKA} type
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static CKA GetAttributeValue(int session, int object, int cka) {
        CKA[] templ = {new CKA(cka)};
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv == CKR.ATTRIBUTE_TYPE_INVALID || templ[0].ulValueLen == 0) {
            return templ[0];
        }
        if (rv != CKR.OK) throw new CKRException(rv);

        // allocate memory and call again
        templ[0].pValue = new Memory(templ[0].ulValueLen);
        rv = C.GetAttributeValue(session, object, templ);
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
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static CKA[] GetAttributeValue(int session, int object, int... types) {
        if (types == null || types.length == 0) {
            return new CKA[0];
        }
        CKA[] templ = new CKA[types.length];
        for (int i = 0; i < types.length; i++) {
            templ[i] = new CKA(types[i], null);
        }

        // try getting all at once
        try {
            GetAttributeValue(session, object, templ);
            // allocate memory and go again
            for (CKA att : templ) {
                att.pValue = att.ulValueLen > 0 ? new Memory(att.ulValueLen) : null;
            }
            GetAttributeValue(session, object, templ);
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
            result[i] = GetAttributeValue(session, object, types[i]);
        }
        return result;
    }

    /**
     * Modifies the values of one or more object attributes.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ specifies attriutes and values
     * @see C#SetAttributeValue(int, int, CKA[])
     * @see Native#C_SetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void SetAttributeValue(int session, int object, CKA... templ) {
        int rv = C.SetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Initailses a search for token and sesion objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @see C#FindObjectsInit(int, CKA[])
     * @see Native#C_FindObjectsInit(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void FindObjectsInit(int session, CKA... templ) {
        int rv = C.FindObjectsInit(session, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @see C#FindObjects(int, int[], LongRef)
     * @see Native#C_FindObjects(com.sun.jna.NativeLong, LongArray, com.sun.jna.NativeLong, LongRef)
     */
    public static void FindObjects(int session, int[] found, LongRef objectCount) {
        int rv = C.FindObjects(session, found, objectCount);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a searc for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param maxObjects maximum objects to return
     * @return list of object handles
     * @see C#FindObjects(int, int[], LongRef)
     * @see Native#C_FindObjects(com.sun.jna.NativeLong, LongArray, com.sun.jna.NativeLong, LongRef)
     */
    public static int[] FindObjects(int session, int maxObjects) {
        int[] found = new int[maxObjects];
        LongRef len = new LongRef();
        FindObjects(session, found, len);
        int count = len.val();
        if (count == maxObjects) {
            return found;
        } else {
            int[] result = new int[count];
            System.arraycopy(found, 0, result, 0, result.length);
            return result;
        }
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @see C#FindObjectsFinal(int)
     * @see Native#C_FindObjectsFinal(com.sun.jna.NativeLong)
     */
    public static void FindObjectsFinal(int session) {
        int rv = C.FindObjectsFinal(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Single-part search for token and sesion objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return all objects matching
     * @see C#FindObjectsInit(int, CKA[])
     * @see Native#C_FindObjectsInit(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static int[] FindObjectsSinglePart(int session, CKA... templ) {
        FindObjectsInit(session, templ);
        int maxObjects = 1024;
        // call once
        int[] result = FindObjects(session, maxObjects);
        // most likely we are done now
        if (result.length < maxObjects) {
            FindObjectsFinal(session);
            return result;
        }

        // this is a lot of objects!
        while (true) {
            maxObjects *= 2;
            int[] found = FindObjects(session, maxObjects);
            int[] temp = new int[result.length + found.length];
            System.arraycopy(result, 0, temp, 0, result.length);
            System.arraycopy(found, 0, temp, result.length, found.length);
            result = temp;
            if (found.length < maxObjects) { // exhausted
                FindObjectsFinal(session);
                return result;
            }
        }
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @see C#EncryptInit(int, CKM, int)
     * @see Native#C_EncryptInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void EncryptInit(int session, CKM mechanism, int key) {
        int rv = C.EncryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @see C#Encrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Encrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Encrypt(int session, byte[] data, byte[] encrypted_data, LongRef encrypted_data_len) {
        int rv = C.Encrypt(session, data, encrypted_data, encrypted_data_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Encrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Encrypt(int session, byte[] data) {
        LongRef l = new LongRef();
        Encrypt(session, data, null, l);
        byte[] result = new byte[l.val()];
        Encrypt(session, data, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart get ciphertext
     * @param encryptedPartLen gets c-text size
     * @see C#EncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_EncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void EncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        int rv = C.EncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part encryption.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#EncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_EncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] EncryptUpdate(int session, byte[] part) {
        LongRef l = new LongRef();
        EncryptUpdate(session, part, null, l);
        byte[] result = new byte[l.val()];
        EncryptUpdate(session, part, result, l);
        return resize(result, l.val());
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @param lastEncryptedPart last c-text
     * @param lastEncryptedPartLen gets last size
     * @see C#EncryptFinal(int, byte[], LongRef)
     * @see Native#C_EncryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void EncryptFinal(int session, byte[] last_encrypted_part, LongRef last_encrypted_part_len) {
        int rv = C.EncryptFinal(session, last_encrypted_part, last_encrypted_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part encryption.
     * @param session the session's handle
     * @return last encrypted part
     * @see C#EncryptFinal(int, byte[], LongRef)
     * @see Native#C_EncryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] EncryptFinal(int session) {
        LongRef l = new LongRef();
        EncryptFinal(session, null, l);
        byte[] result = new byte[l.val()];
        EncryptFinal(session, result, l);
        return resize(result, l.val());
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @param data the plaintext data
     * @return encrypted data
     * @see C#Encrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Encrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Encrypt(int session, CKM mechanism, int key, byte[] data) {
        EncryptInit(session, mechanism, key);
        return Encrypt(session, data);
    }

    /**
     * Intialises a decryption operation.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @see C#DecryptInit(int, CKM, int)
     * @see Native#C_DecryptInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void DecryptInit(int session, CKM mechanism, int key) {
        int rv = C.DecryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @see C#Decrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Decrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Decrypt(int session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        int rv = C.Decrypt(session, encryptedData, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);

    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Decrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Decrypt(int session, byte[] encryptedData) {
        LongRef l = new LongRef();
        Decrypt(session, encryptedData, null, l);
        byte[] result = new byte[l.val()];
        Decrypt(session, encryptedData, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @param data gets plaintext
     * @param dataLen get p-text size
     * @see C#DecryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptUpdate(int session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        int rv = C.DecryptUpdate(session, encryptedPart, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption.
     * @param session the session's handle
     * @param encryptedPart encrypted data
     * @return plaintext
     * @see C#DecryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptUpdate(int session, byte[] encrypted_part) {
        LongRef l = new LongRef();
        DecryptUpdate(session, encrypted_part, null, l);
        byte[] result = new byte[l.val()];
        DecryptUpdate(session, encrypted_part, result, l);
        return resize(result, l.val());
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @param lastPart gets plaintext
     * @param lastPartLen p-text size
     * @see C#DecryptFinal(int, byte[], LongRef)
     * @see Native#C_DecryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptFinal(int session, byte[] lastPart, LongRef lastPartLen) {
        int rv = C.DecryptFinal(session, lastPart, lastPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part decryption.
     * @param session the session's handle
     * @return last part of plaintext
     * @see C#DecryptFinal(int, byte[], LongRef)
     * @see Native#C_DecryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptFinal(int session) {
        LongRef l = new LongRef();
        DecryptFinal(session, null, l);
        byte[] result = new byte[l.val()];
        DecryptFinal(session, result, l);
        return resize(result, l.val());
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param mechanism the decryption mechanism
     * @param key handle of decryption key
     * @param encryptedData cipertext
     * @return plaintext
     * @see C#Decrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Decrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Decrypt(int session, CKM mechanism, int key, byte[] encryptedData) {
        DecryptInit(session, mechanism, key);
        return Decrypt(session, encryptedData);
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @see C#DigestInit(int, CKM)
     * @see Native#C_DigestInit(com.sun.jna.NativeLong, CKM)
     */
    public static void DigestInit(int session, CKM mechanism) {
        int rv = C.DigestInit(session, mechanism);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @see C#Digest(int, byte[], byte[], LongRef)
     * @see Native#C_Digest(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Digest(int session, byte[] data, byte[] digest, LongRef digestLen) {
        int rv = C.Digest(session, data, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @return digest
     * @see C#Digest(int, byte[], byte[], LongRef)
     * @see Native#C_Digest(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Digest(int session, byte[] data) {
        LongRef l = new LongRef();
        Digest(session, data, null, l);
        byte[] result = new byte[l.val()];
        Digest(session, data, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @see C#DigestUpdate(int, byte[])
     * @see Native#C_DigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void DigestUpdate(int session, byte[] part) {
        int rv = C.DigestUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @see C#DigestKey(int, int)
     * @see Native#C_DigestKey(com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void DigestKey(int session, int key) {
        int rv = C.DigestKey(session, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @see C#DigestFinal(int, byte[], LongRef)
     * @see Native#C_DigestFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DigestFinal(int session, byte[] digest, LongRef digestLen) {
        int rv = C.DigestFinal(session, digest, digestLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @return digest
     * @see C#DigestFinal(int, byte[], LongRef)
     * @see Native#C_DigestFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DigestFinal(int session) {
        LongRef l = new LongRef();
        DigestFinal(session, null, l);
        byte[] result = new byte[l.val()];
        DigestFinal(session, result, l);
        return resize(result, l.val());
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @param data data to be digested
     * @return digest
     * @see C#Digest(int, byte[], byte[], LongRef)
     * @see Native#C_Digest(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Digest(int session, CKM mechanism, byte[] data) {
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
     * @see C#SignInit(int, CKM, int)
     * @see Native#C_SignInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void SignInit(int session, CKM mechanism, int key) {
        int rv = C.SignInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#Sign(int, byte[], byte[], LongRef)
     * @see Native#C_Sign(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Sign(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        int rv = C.Sign(session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#Sign(int, byte[], byte[], LongRef)
     * @see Native#C_Sign(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Sign(int session, byte[] data) {
        LongRef l = new LongRef();
        Sign(session, data, null, l);
        byte[] result = new byte[l.val()];
        Sign(session, data, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param session the session's handle
     * @param part data to sign
     * @see C#SignUpdate(int, byte[])
     * @see Native#C_SignUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SignUpdate(int session, byte[] part) {
        int rv = C.SignUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignFinal(int, byte[], LongRef)
     * @see Native#C_SignFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignFinal(int session, byte[] signature, LongRef signatureLen) {
        int rv = C.SignFinal(session, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @return signature
     * @see C#SignFinal(int, byte[], LongRef)
     * @see Native#C_SignFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] SignFinal(int session) {
        LongRef l = new LongRef();
        SignFinal(session, null, l);
        byte[] result = new byte[l.val()];
        SignFinal(session, result, l);
        return resize(result, l.val());
    }

    /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle of signature key
     * @param data the data to sign
     * @return signature
     * @see C#Sign(int, byte[], byte[], LongRef)
     * @see Native#C_Sign(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Sign(int session, CKM mechanism, int key, byte[] data) {
        SignInit(session, mechanism, key);
        return Sign(session, data);
    }

    /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @see C#SignRecoverInit(int, CKM, int)
     * @see Native#C_SignRecoverInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void SignRecoverInit(int session, CKM mechanism, int key) {
        int rv = C.SignRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @see C#SignRecover(int, byte[], byte[], LongRef)
     * @see Native#C_SignRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignRecover(int session, byte[] data, byte[] signature, LongRef signatureLen) {
        int rv = C.SignRecover(session, data, signature, signatureLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(int, byte[], byte[], LongRef)
     * @see Native#C_SignRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] SignRecover(int session, byte[] data) {
        LongRef l = new LongRef();
        SignRecover(session, data, null, l);
        byte[] result = new byte[l.val()];
        SignRecover(session, data, result, l);
        return resize(result, l.val());
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param mechanism the signature mechanism
     * @param key handle f the signature key
     * @param data the data to sign
     * @return signature
     * @see C#SignRecover(int, byte[], byte[], LongRef)
     * @see Native#C_SignRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] SignRecover(int session, CKM mechanism, int key, byte[] data) {
        SignRecoverInit(session, mechanism, key);
        return SignRecover(session, data);
    }

    /**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature (e.g. DSA).
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyInit(int, CKM, int)
     * @see Native#C_VerifyInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void VerifyInit(int session, CKM mechanism, int key) {
        int rv = C.VerifyInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @see C#Verify(int, byte[], byte[])
     * @see Native#C_Verify(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void Verify(int session, byte[] data, byte[] signature) {
        int rv = C.Verify(session, data, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @see C#VerifyUpdate(int, byte[])
     * @see Native#C_VerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void VerifyUpdate(int session, byte[] part) {
        int rv = C.VerifyUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @see C#VerifyFinal(int, byte[])
     * @see Native#C_VerifyFinal(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void VerifyFinal(int session, byte[] signature) {
        int rv = C.VerifyFinal(session, signature);
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
     * @see C#Verify(int, byte[], byte[])
     * @see Native#C_Verify(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void Verify(int session, CKM mechanism, int key, byte[] data, byte[] signature) {
        VerifyInit(session, mechanism, key);
        Verify(session, data, signature);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @see C#VerifyRecoverInit(int, CKM, int)
     * @see Native#C_VerifyRecoverInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void VerifyRecoverInit(int session, CKM mechanism, int key) {
        int rv = C.VerifyRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @see C#VerifyRecover(int, byte[], byte[], LongRef)
     * @see Native#C_VerifyRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void VerifyRecover(int session, byte[] signature, byte[] data, LongRef dataLen) {
        int rv = C.VerifyRecover(session, signature, data, dataLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(int, byte[], byte[], LongRef)
     * @see Native#C_VerifyRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] VerifyRecover(int session, byte[] signature) {
        LongRef l = new LongRef();
        VerifyRecover(session, signature, null, l);
        byte[] result = new byte[l.val()];
        VerifyRecover(session, signature, result, l);
        return resize(result, l.val());
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @param signature signature to verify
     * @return data
     * @see C#VerifyRecover(int, byte[], byte[], LongRef)
     * @see Native#C_VerifyRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] VerifyRecover(int session, CKM mechanism, int key, byte[] signature) {
        VerifyRecoverInit(session, mechanism, key);
        return VerifyRecover(session, signature);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen get c-text length
     * @see C#DigestEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DigestEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DigestEncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        int rv = C.DigestEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part digesting and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#DigestEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DigestEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DigestEncryptUpdate(int session, byte[] part) {
        LongRef l = new LongRef();
        DigestEncryptUpdate(session, part, null, l);
        byte[] result = new byte[l.val()];
        DigestEncryptUpdate(session, part, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets plaintext length
     * @see C#DigestUpdate(int, byte[])
     * @see Native#C_DigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void DecryptDigestUpdate(int session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        int rv = C.DecryptDigestUpdate(session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and digesting operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @return plaintext
     * @see C#DecryptDigestUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptDigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptDigestUpdate(int session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptDigestUpdate(session, encryptedPart, null, l);
        byte[] result = new byte[l.val()];
        DecryptDigestUpdate(session, encryptedPart, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @param encryptedPart gets ciphertext
     * @param encryptedPartLen gets c-text length
     * @see C#SignEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_SignEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignEncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        int rv = C.SignEncryptUpdate(session, part, encryptedPart, encryptedPartLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part signing and encryption operation.
     * @param session the session's handle
     * @param part the plaintext data
     * @return encrypted part
     * @see C#SignEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_SignEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] SignEncryptUpdate(int session, byte[] part) {
        LongRef l = new LongRef();
        SignEncryptUpdate(session, part, null, l);
        byte[] result = new byte[l.val()];
        SignEncryptUpdate(session, part, result, l);
        return resize(result, l.val());
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encrypedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @see C#DecryptVerifyUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptVerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptVerifyUpdate(int session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        int rv = C.DecryptVerifyUpdate(session, encryptedPart, part, partLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encrypedPart ciphertext
     * @return plaintext
     * @see C#DecryptVerifyUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptVerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptVerifyUpdate(int session, byte[] encryptedPart) {
        LongRef l = new LongRef();
        DecryptVerifyUpdate(session, encryptedPart, null, l);
        byte[] result = new byte[l.val()];
        DecryptVerifyUpdate(session, encryptedPart, result, l);
        return resize(result, l.val());
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @param key gets handle of new key
     * @see C#GenerateKey(int, CKM, CKA[], LongRef)
     * @see Native#C_GenerateKey(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void GenerateKey(int session, CKM mechanism, CKA[] templ, LongRef key) {
        int rv = C.GenerateKey(session, mechanism, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates a secret key, creating a new key.
     * @param session the session's handle
     * @param mechanism key generation mechanism
     * @param templ template for the new key
     * @return key handle
     * @see C#GenerateKey(int, CKM, CKA[], LongRef)
     * @see Native#C_GenerateKey(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int GenerateKey(int session, CKM mechanism, CKA... templ) {
        LongRef key = new LongRef();
        GenerateKey(session, mechanism, templ, key);
        return key.val();
    }

    /**
     * Generates a public-key / private-key pair, create new key objects.
     * @param session the session's handle
     * @param mechanism key generation mechansim
     * @param publicKeyTemplate template for the new public key
     * @param privateKeyTemplate template for the new private key
     * @param publicKey gets handle of new public key
     * @param privateKey gets handle of new private key
     * @see C#GenerateKeyPair(int, CKM, CKA[], CKA[], LongRef, LongRef)
     * @see Native#C_GenerateKeyPair(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef, LongRef)
     */
    public static void GenerateKeyPair(int session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTempate,
            LongRef publickey, LongRef private_key) {
        int rv = C.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTempate, publickey, private_key);
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
     * @see C#WrapKey(int, CKM, int, int, byte[], LongRef)
     * @see Native#C_WrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void WrapKey(int session, CKM mechanism, int wrappingKey, int key, byte[] wrappedKey, LongRef wrappedKeyLen) {
        int rv = C.WrapKey(session, mechanism, wrappingKey, key, wrappedKey, wrappedKeyLen);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Wraps (encrypts) a key.
     * @param session the session's handle
     * @param mechanism the wrapping mechanism
     * @param wrappingKey wrapping key
     * @param key key to be wrapped
     * @return wrapped key
     * @see C#WrapKey(int, CKM, int, int, byte[], LongRef)
     * @see Native#C_WrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] WrapKey(int session, CKM mechanism, int wrappingKey, int key) {
        LongRef l = new LongRef();
        WrapKey(session, mechanism, wrappingKey, key, null, l);
        byte[] result = new byte[l.val()];
        WrapKey(session, mechanism, wrappingKey, key, result, l);
        return resize(result, l.val());
    }

    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param session the session's handle
     * @param mechanism unwrapping mechanism
     * @param unwrappingKey unwrapping key
     * @param wrappedKey the wrapped key
     * @param templ new key template
     * @param key gets new handle
     * @see C#UnwrapKey(int, CKM, int, byte[], CKA[], LongRef)
     * @see Native#C_UnwrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void UnwrapKey(int session, CKM mechanism, int unwrappingKey, byte[] wrappedKey, CKA[] templ, LongRef key) {
        int rv = C.UnwrapKey(session, mechanism, unwrappingKey, wrappedKey, templ, key);
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
     * @see C#UnwrapKey(int, CKM, int, byte[], CKA[], LongRef)
     * @see Native#C_UnwrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int UnwrapKey(int session, CKM mechanism, int unwrapping_key, byte[] wrapped_key, CKA... templ) {
        LongRef result = new LongRef();
        UnwrapKey(session, mechanism, unwrapping_key, wrapped_key, templ, result);
        return result.val();
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @param key ges new handle
     * @see C#DeriveKey(int, CKM, int, CKA[], LongRef)
     * @see Native#C_DeriveKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void DeriveKey(int session, CKM mechanism, int baseKey, CKA[] templ, LongRef key) {
        int rv = C.DeriveKey(session, mechanism, baseKey, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Derives a key from a base key, creating a new key object.
     * @param session the session's handle
     * @param mechanism key derivation mechanism
     * @param baseKey base key
     * @param templ new key template
     * @return new handle
     * @see C#DeriveKey(int, CKM, int, CKA[], LongRef)
     * @see Native#C_DeriveKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int DeriveKey(int session, CKM mechanism, int base_key, CKA... templ) {
        LongRef key = new LongRef();
        DeriveKey(session, mechanism, base_key, templ, key);
        return key.val();
    }

    /**
     * Mixes additional seed material into the token’s random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @see C#SeedRandom(int, byte[])
     * @see Native#C_SeedRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SeedRandom(int session, byte[] seed) {
        int rv = C.SeedRandom(session, seed);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @see C#GenerateRandom(int, byte[])
     * @see Native#C_GenerateRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void GenerateRandom(int session, byte[] randomData) {
        int rv = C.GenerateRandom(session, randomData);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomLen number of bytes of random to generate
     * @return random
     * @see C#GenerateRandom(int, byte[])
     * @see Native#C_GenerateRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static byte[] GenerateRandom(int session, int randomLen) {
        byte[] result = new byte[randomLen];
        GenerateRandom(session, result);
        return result;
    }

    /**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(int)
     * @see Native#C_GetFunctionStatus(com.sun.jna.NativeLong)
     */
    public static void GetFunctionStatus(int session) {
        int rv = C.GetFunctionStatus(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @see C#GetFunctionStatus(int)
     * @see Native#C_GetFunctionStatus(com.sun.jna.NativeLong)
     */
    public static void CancelFunction(int session) {
        int rv = C.CancelFunction(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     * Resize buf to specified length. If buf already size 'newSize', then return buf, else return resized buf.
     * @param buf buf
     * @param newSize length to resize to
     * @return if buf already size 'newSize', then return buf, else return resized buf
     */
    private static byte[] resize(byte[] buf, int newSize) {
        if (buf == null || newSize >= buf.length) {
            return buf;
        }
        byte[] result = new byte[newSize];
        System.arraycopy(buf, 0, result, 0, result.length);
        return result;
    }
}
