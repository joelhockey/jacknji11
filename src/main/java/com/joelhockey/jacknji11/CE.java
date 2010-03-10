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
     *
     * @see C#Finalize()
     * @see Native#C_Finalize(Pointer)
     */
    public static void Finalize() {
        int rv = C.Finalize();
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param info
     * @see C#GetInfo(CK_INFO)
     * @see Native#C_GetInfo(CK_INFO)
     */
    public static void GetInfo(CK_INFO info) {
        int rv = C.GetInfo(info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param tokenPresent
     * @param slotList
     * @param count
     * @see C#GetSlotList(boolean, int[], LongRef)
     * @see Native#C_GetSlotList(byte, LongArray, LongRef)
     */
    public static void GetSlotList(boolean tokenPresent, int[] slotList, LongRef count) {
        int rv = C.GetSlotList(tokenPresent, slotList, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param tokenPresent
     * @return
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
     *
     * @param slotID
     * @param info
     * @see C#GetSlotInfo(int, CK_SLOT_INFO)
     * @see Native#C_GetSlotInfo(com.sun.jna.NativeLong, CK_SLOT_INFO)
     */
    public static void GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = C.GetSlotInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @param info
     * @see C#GetTokenInfo(int, CK_TOKEN_INFO)
     * @see Native#C_GetTokenInfo(com.sun.jna.NativeLong, CK_TOKEN_INFO)
     */
    public static void GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = C.GetTokenInfo(slotID, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param flags
     * @param slot
     * @param pReserved
     * @see C#WaitForSlotEvent(int, LongRef, Pointer)
     * @see Native#C_WaitForSlotEvent(com.sun.jna.NativeLong, LongRef, Pointer)
     */
    public static void WaitForSlotEvent(int flags, LongRef slot, Pointer pReserved) {
        int rv = C.WaitForSlotEvent(flags, slot, pReserved);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @param mechanism_list
     * @param count
     * @see C#GetMechanismList(int, int[], LongRef)
     * @see Native#C_GetMechanismList(com.sun.jna.NativeLong, LongArray, LongRef)
     */
    public static void GetMechanismList(int slotID, int[] mechanism_list, LongRef count) {
        int rv = C.GetMechanismList(slotID, mechanism_list, count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @return
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
     *
     * @param slotID
     * @param type
     * @param info
     * @see C#GetMechanismInfo(int, int, CK_MECHANISM_INFO)
     * @see Native#C_GetMechanismInfo(com.sun.jna.NativeLong, com.sun.jna.NativeLong, CK_MECHANISM_INFO)
     */
    public static void GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        int rv = C.GetMechanismInfo(slotID, type, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slot_id
     * @param pin
     * @param label
     * @see C#InitToken(int, byte[], byte[])
     * @see Native#C_InitToken(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[])
     */
    public static void InitToken(int slot_id, byte[] pin, byte[] label) {
        int rv = C.InitToken(slot_id, pin, label);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param pin
     * @see C#InitPIN(int, byte[])
     * @see Native#C_InitPIN(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void InitPIN(int session, byte[] pin) {
        int rv = C.InitPIN(session, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param old_pin
     * @param new_pin
     * @see C#SetPIN(int, byte[], byte[])
     * @see Native#C_SetPIN(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SetPIN(int session, byte[] old_pin, byte[] new_pin) {
        int rv = C.SetPIN(session, old_pin, new_pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @param flags
     * @param application
     * @param notify
     * @param session
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static void OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        int rv = C.OpenSession(slotID, flags, application, notify, session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @param flags
     * @param application
     * @param notify
     * @return
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify) {
        LongRef session = new LongRef();
        OpenSession(slotID, flags, application, notify, session);
        return session.val();
    }

    /**
     *
     * @param slotID
     * @return
     * @see C#OpenSession(int, int, Pointer, CK_NOTIFY, LongRef)
     * @see Native#C_OpenSession(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Pointer, CK_NOTIFY, LongRef)
     */
    public static int OpenSession(int slotID) {
        return OpenSession(slotID, CKS.RW_PUBLIC_SESSION, null, null);
    }

    /**
     *
     * @param session
     * @see C#
     * @see Native#C_
     */
    public static void CloseSession(int session) {
        int rv = C.CloseSession(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param slotID
     * @see C#CloseAllSessions(int)
     * @see Native#C_CloseAllSessions(com.sun.jna.NativeLong)
     */
    public static void CloseAllSessions(int slotID) {
        int rv = C.CloseAllSessions(slotID);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param info
     * @see C#GetSessionInfo(int, CK_SESSION_INFO)
     * @see Native#C_GetSessionInfo(com.sun.jna.NativeLong, CK_SESSION_INFO)
     */
    public static void GetSessionInfo(int session, CK_SESSION_INFO info) {
        int rv = C.GetSessionInfo(session, info);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param operation_state
     * @param operation_state_len
     * @see C#GetOperationState(int, byte[], LongRef)
     * @see Native#C_GetOperationState(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void GetOperationState(int session, byte[] operation_state, LongRef operation_state_len) {
        int rv = C.GetOperationState(session, operation_state, operation_state_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param operation_state
     * @param encryption_key
     * @param authentication_key
     * @see C#SetOperationState(int, byte[], int, int)
     * @see Native#C_SetOperationState(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void SetOperationState(int session, byte[] operation_state, int encryption_key, int authentication_key) {
        int rv = C.SetOperationState(session, operation_state, encryption_key, authentication_key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param user_type
     * @param pin
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void Login(int session, int user_type, byte[] pin) {
        int rv = C.Login(session, user_type, pin);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param pin
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void LoginUser(int session, byte[] pin) {
        Login(session, CKU.USER, pin);
    }

    /**
     *
     * @param session
     * @param pin
     * @see C#Login(int, int, byte[])
     * @see Native#C_Login(com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void LoginSO(int session, byte[] pin) {
        Login(session, CKU.SO, pin);
    }

    /**
     *
     * @param session
     * @see C#Logout(int)
     * @see Native#C_Logout(com.sun.jna.NativeLong)
     */
    public static void Logout(int session) {
        int rv = C.Logout(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param templ
     * @param object
     * @see C#CreateObject(int, CKA[], LongRef)
     * @see Native#C_CreateObject(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void CreateObject(int session, CKA[] templ, LongRef object) {
        int rv = C.CreateObject(session, templ, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param templ
     * @return
     * @see C#CreateObject(int, CKA[], LongRef)
     * @see Native#C_CreateObject(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int CreateObject(int session, CKA... templ) {
        LongRef object = new LongRef();
        CreateObject(session, templ, object);
        return object.val();
    }

    /**
     *
     * @param session
     * @param object
     * @param templ
     * @param new_object
     * @see C#CopyObject(int, int, CKA[], LongRef)
     * @see Native#C_CopyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void CopyObject(int session, int object, CKA[] templ, LongRef new_object) {
        int rv = C.CopyObject(session, object, templ, new_object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param object
     * @param templ
     * @return
     * @see C#CopyObject(int, int, CKA[], LongRef)
     * @see Native#C_CopyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int CopyObject(int session, int object, CKA... templ) {
        LongRef new_object = new LongRef();
        CopyObject(session, object, templ, new_object);
        return new_object.val();
    }

    /**
     *
     * @param session
     * @param object
     * @see C#DestroyObject(int, int)
     * @see Native#C_DestroyObject(com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void DestroyObject(int session, int object) {
        int rv = C.DestroyObject(session, object);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param object
     * @param size
     * @see C#GetObjectSize(int, int, LongRef)
     * @see Native#C_GetObjectSize(com.sun.jna.NativeLong, com.sun.jna.NativeLong, LongRef)
     */
    public static void GetObjectSize(int session, int object, LongRef size) {
        int rv = C.GetObjectSize(session, object, size);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param object
     * @return
     * @see C#GetObjectSize(int, int, LongRef)
     * @see Native#C_GetObjectSize(com.sun.jna.NativeLong, com.sun.jna.NativeLong, LongRef)
     */
    public static int GetObjectSize(int session, int object) {
        LongRef size = new LongRef();
        GetObjectSize(session, object, size);
        return size.val();
    }

    /**
     *
     * @param session
     * @param object
     * @param templ
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void GetAttributeValue(int session, int object, CKA... templ) {
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param object
     * @param types
     * @return
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static CKA[] GetAttributeValue(int session, int object, int... types) {
        if (types == null || types.length == 0)
            return new CKA[0];
        CKA[] templ = new CKA[types.length];
        for (int i = 0; i < types.length; i++) {
            templ[i] = new CKA(types[i], null);
        }
        GetAttributeValue(session, object, templ);
        // allocate memory and go again
        for (CKA att : templ) {
            att.pValue = att.ulValueLen > 0 ? new Memory(att.ulValueLen) : null;
        }
        GetAttributeValue(session, object, templ);
        return templ;
    }

    /**
     *
     * @param session
     * @param object
     * @param ckaType
     * @return
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static byte[] GetAttributeValueBuf(int session, int object, int ckaType) {
        CKA att = new CKA(ckaType, null);
        CKA[] templ = { att };
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv == -1 || rv == CKR.ATTRIBUTE_TYPE_INVALID)
            return null; // null if attribute not exists or cannot be extracted
        if (rv != CKR.OK) throw new CKRException(rv);

        // allocate memory and go again
        if (att.ulValueLen == 0)
            return new byte[0];
        att.pValue = new Memory(att.ulValueLen);
        rv = C.GetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);

        return att.getValue();
    }

    /**
     *
     * @param session
     * @param object
     * @param ckaType
     * @return
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static String GetAttributeValueStr(int session, int object, int ckaType) {
        byte[] buf = GetAttributeValueBuf(session, object, ckaType);
        return buf == null ? null : new String(buf);
    }

    /**
     *
     * @param session
     * @param object
     * @param ckaType
     * @return
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static Integer GetAttributeValueInt(int session, int object, int ckaType) {
        CKA att = new CKA(ckaType, 0);
        CKA[] templ = { att };
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv == -1 || rv == CKR.ATTRIBUTE_TYPE_INVALID)
            return null; // null if attribute not exists or cannot be extracted
        if (rv != CKR.OK) throw new CKRException(rv);

        // allocate memory and go again
        att.pValue = new Memory(att.ulValueLen);
        rv = C.GetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        return att.getValueInt();
    }

    /**
     *
     * @param session
     * @param object
     * @param ckaType
     * @return
     * @see C#GetAttributeValue(int, int, CKA[])
     * @see Native#C_GetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static Boolean GetAttributeValueBool(int session, int object, int ckaType) {
        CKA att = new CKA(ckaType, 0);
        CKA[] templ = { att };
        int rv = C.GetAttributeValue(session, object, templ);
        if (rv == -1 || rv == CKR.ATTRIBUTE_TYPE_INVALID)
            return null; // null if attribute not exists or cannot be extracted
        if (rv != CKR.OK) throw new CKRException(rv);
        // allocate memory and go again
        att.pValue = new Memory(att.ulValueLen);
        rv = C.GetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
        return att.getValueBool();
    }

    /**
     *
     * @param session
     * @param object
     * @param templ
     * @see C#SetAttributeValue(int, int, CKA[])
     * @see Native#C_SetAttributeValue(com.sun.jna.NativeLong, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void SetAttributeValue(int session, int object, CKA... templ) {
        int rv = C.SetAttributeValue(session, object, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param templ
     * @see C#FindObjectsInit(int, CKA[])
     * @see Native#C_FindObjectsInit(com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong)
     */
    public static void FindObjectsInit(int session, CKA... templ) {
        int rv = C.FindObjectsInit(session, templ);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param found
     * @param object_count
     * @see C#FindObjects(int, int[], LongRef)
     * @see Native#C_FindObjects(com.sun.jna.NativeLong, LongArray, com.sun.jna.NativeLong, LongRef)
     */
    public static void FindObjects(int session, int[] found, LongRef object_count) {
        int rv = C.FindObjects(session, found, object_count);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param maxObjects
     * @return
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
     *
     * @param session
     * @see C#FindObjectsFinal(int)
     * @see Native#C_FindObjectsFinal(com.sun.jna.NativeLong)
     */
    public static void FindObjectsFinal(int session) {
        int rv = C.FindObjectsFinal(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#EncryptInit(int, CKM, int)
     * @see Native#C_EncryptInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void EncryptInit(int session, CKM mechanism, int key) {
        int rv = C.EncryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @param encrypted_data
     * @param encrypted_data_len
     * @see C#Encrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Encrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Encrypt(int session, byte[] data, byte[] encrypted_data, LongRef encrypted_data_len) {
        int rv = C.Encrypt(session, data, encrypted_data, encrypted_data_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @return
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
     *
     * @param session
     * @param part
     * @param encrypted_part
     * @param encrypted_part_len
     * @see C#EncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_EncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void EncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        int rv = C.EncryptUpdate(session, part, encrypted_part, encrypted_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param part
     * @return
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
     *
     * @param session
     * @param last_encrypted_part
     * @param last_encrypted_part_len
     * @see C#EncryptFinal(int, byte[], LongRef)
     * @see Native#C_EncryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void EncryptFinal(int session, byte[] last_encrypted_part, LongRef last_encrypted_part_len) {
        int rv = C.EncryptFinal(session, last_encrypted_part, last_encrypted_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @return
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
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#DecryptInit(int, CKM, int)
     * @see Native#C_DecryptInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void DecryptInit(int session, CKM mechanism, int key) {
        int rv = C.DecryptInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param encrypted_data
     * @param data
     * @param data_lens
     * @see C#Decrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Decrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Decrypt(int session, byte[] encrypted_data, byte[] data, LongRef data_lens) {
        int rv = C.Decrypt(session, encrypted_data, data, data_lens);
        if (rv != CKR.OK) throw new CKRException(rv);

    }

    /**
     *
     * @param session
     * @param encrypted_data
     * @return
     * @see C#Decrypt(int, byte[], byte[], LongRef)
     * @see Native#C_Decrypt(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] Decrypt(int session, byte[] encrypted_data) {
        LongRef l = new LongRef();
        Decrypt(session, encrypted_data, null, l);
        byte[] result = new byte[l.val()];
        Decrypt(session, encrypted_data, result, l);
        return resize(result, l.val());
    }

    /**
     *
     * @param session
     * @param encrypted_part
     * @param data
     * @param data_len
     * @see C#DecryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptUpdate(int session, byte[] encrypted_part, byte[] data, LongRef data_len) {
        int rv = C.DecryptUpdate(session, encrypted_part, data, data_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param encrypted_part
     * @return
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
     *
     * @param session
     * @param last_part
     * @param last_part_len
     * @see C#DecryptFinal(int, byte[], LongRef)
     * @see Native#C_DecryptFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptFinal(int session, byte[] last_part, LongRef last_part_len) {
        int rv = C.DecryptFinal(session, last_part, last_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @return
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
     *
     * @param session
     * @param mechanism
     * @see C#DigestInit(int, CKM)
     * @see Native#C_DigestInit(com.sun.jna.NativeLong, CKM)
     */
    public static void DigestInit(int session, CKM mechanism) {
        int rv = C.DigestInit(session, mechanism);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @param digest
     * @param digest_len
     * @see C#Digest(int, byte[], byte[], LongRef)
     * @see Native#C_Digest(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Digest(int session, byte[] data, byte[] digest, LongRef digest_len) {
        int rv = C.Digest(session, data, digest, digest_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @return
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
     *
     * @param session
     * @param part
     * @see C#DigestUpdate(int, byte[])
     * @see Native#C_DigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void DigestUpdate(int session, byte[] part) {
        int rv = C.DigestUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param key
     * @see C#DigestKey(int, int)
     * @see Native#C_DigestKey(com.sun.jna.NativeLong, com.sun.jna.NativeLong)
     */
    public static void DigestKey(int session, int key) {
        int rv = C.DigestKey(session, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param digest
     * @param digest_len
     * @see C#DigestFinal(int, byte[], LongRef)
     * @see Native#C_DigestFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DigestFinal(int session, byte[] digest, LongRef digest_len) {
        int rv = C.DigestFinal(session, digest, digest_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @return
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
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#SignInit(int, CKM, int)
     * @see Native#C_SignInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void SignInit(int session, CKM mechanism, int key) {
        int rv = C.SignInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @param signature
     * @param signature_len
     * @see C#Sign(int, byte[], byte[], LongRef)
     * @see Native#C_Sign(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void Sign(int session, byte[] data, byte[] signature, LongRef signature_len) {
        int rv = C.Sign(session, data, signature, signature_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @return
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
     *
     * @param session
     * @param part
     * @see C#SignUpdate(int, byte[])
     * @see Native#C_SignUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SignUpdate(int session, byte[] part) {
        int rv = C.SignUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param signature
     * @param signature_len
     * @see C#SignFinal(int, byte[], LongRef)
     * @see Native#C_SignFinal(com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignFinal(int session, byte[] signature, LongRef signature_len) {
        int rv = C.SignFinal(session, signature, signature_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @return
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
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#SignRecoverInit(int, CKM, int)
     * @see Native#C_SignRecoverInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void SignRecoverInit(int session, CKM mechanism, int key) {
        int rv = C.SignRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @param signature
     * @param signature_len
     * @see C#SignRecover(int, byte[], byte[], LongRef)
     * @see Native#C_SignRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignRecover(int session, byte[] data, byte[] signature, LongRef signature_len) {
        int rv = C.SignRecover(session, data, signature, signature_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @return
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
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#VerifyInit(int, CKM, int)
     * @see Native#C_VerifyInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void VerifyInit(int session, CKM mechanism, int key) {
        int rv = C.VerifyInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param data
     * @param signature
     * @see C#Verify(int, byte[], byte[])
     * @see Native#C_Verify(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void Verify(int session, byte[] data, byte[] signature) {
        int rv = C.Verify(session, data, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param part
     * @see C#VerifyUpdate(int, byte[])
     * @see Native#C_VerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void VerifyUpdate(int session, byte[] part) {
        int rv = C.VerifyUpdate(session, part);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param signature
     * @see C#VerifyFinal(int, byte[])
     * @see Native#C_VerifyFinal(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void VerifyFinal(int session, byte[] signature) {
        int rv = C.VerifyFinal(session, signature);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param key
     * @see C#VerifyRecoverInit(int, CKM, int)
     * @see Native#C_VerifyRecoverInit(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong)
     */
    public static void VerifyRecoverInit(int session, CKM mechanism, int key) {
        int rv = C.VerifyRecoverInit(session, mechanism, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param signature
     * @param data
     * @param data_len
     * @see C#VerifyRecover(int, byte[], byte[], LongRef)
     * @see Native#C_VerifyRecover(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void VerifyRecover(int session, byte[] signature, byte[] data, LongRef data_len) {
        int rv = C.VerifyRecover(session, signature, data, data_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param signature
     * @return
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
     *
     * @param session
     * @param part
     * @param encrypted_part
     * @param encrypted_part_len
     * @see C#DigestEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DigestEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DigestEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        int rv = C.DigestEncryptUpdate(session, part, encrypted_part, encrypted_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param part
     * @return
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
     *
     * @param session
     * @param encrypted_part
     * @param part
     * @param part_len
     * @see C#DigestUpdate(int, byte[])
     * @see Native#C_DigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void DecryptDigestUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        int rv = C.DecryptDigestUpdate(session, encrypted_part, part, part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param encrypted_part
     * @return
     * @see C#DecryptDigestUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptDigestUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptDigestUpdate(int session, byte[] encrypted_part) {
        LongRef l = new LongRef();
        DecryptDigestUpdate(session, encrypted_part, null, l);
        byte[] result = new byte[l.val()];
        DecryptDigestUpdate(session, encrypted_part, result, l);
        return resize(result, l.val());
    }

    /**
     *
     * @param session
     * @param part
     * @param encrypted_part
     * @param encrypted_part_len
     * @see C#SignEncryptUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_SignEncryptUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void SignEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        int rv = C.SignEncryptUpdate(session, part, encrypted_part, encrypted_part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param part
     * @return
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
     *
     * @param session
     * @param encrypted_part
     * @param part
     * @param part_len
     * @see C#DecryptVerifyUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptVerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void DecryptVerifyUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        int rv = C.DecryptVerifyUpdate(session, encrypted_part, part, part_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session session handle
     * @param encrypted_part
     * @return
     * @see C#DecryptVerifyUpdate(int, byte[], byte[], LongRef)
     * @see Native#C_DecryptVerifyUpdate(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] DecryptVerifyUpdate(int session, byte[] encrypted_part) {
        LongRef l = new LongRef();
        DecryptVerifyUpdate(session, encrypted_part, null, l);
        byte[] result = new byte[l.val()];
        DecryptVerifyUpdate(session, encrypted_part, result, l);
        return resize(result, l.val());
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param templ
     * @param key
     * @see C#GenerateKey(int, CKM, CKA[], LongRef)
     * @see Native#C_GenerateKey(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void GenerateKey(int session, CKM mechanism, CKA[] templ, LongRef key) {
        int rv = C.GenerateKey(session, mechanism, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param templ
     * @return
     * @see C#GenerateKey(int, CKM, CKA[], LongRef)
     * @see Native#C_GenerateKey(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int GenerateKey(int session, CKM mechanism, CKA... templ) {
        LongRef key = new LongRef();
        GenerateKey(session, mechanism, templ, key);
        return key.val();
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param publicKeyTemplate
     * @param privateKeyTempate
     * @param publickey
     * @param private_key
     * @see C#GenerateKeyPair(int, CKM, CKA[], CKA[], LongRef, LongRef)
     * @see Native#C_GenerateKeyPair(com.sun.jna.NativeLong, CKM, Template, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef, LongRef)
     */
    public static void GenerateKeyPair(int session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTempate,
            LongRef publickey, LongRef private_key) {
        int rv = C.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTempate, publickey, private_key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param wrapping_key
     * @param key
     * @param wrapped_key
     * @param wrapped_key_len
     * @see C#WrapKey(int, CKM, int, int, byte[], LongRef)
     * @see Native#C_WrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static void WrapKey(int session, CKM mechanism, int wrapping_key, int key, byte[] wrapped_key, LongRef wrapped_key_len) {
        int rv = C.WrapKey(session, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param wrapping_key
     * @param key
     * @return
     * @see C#WrapKey(int, CKM, int, int, byte[], LongRef)
     * @see Native#C_WrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, com.sun.jna.NativeLong, byte[], LongRef)
     */
    public static byte[] WrapKey(int session, CKM mechanism, int wrapping_key, int key) {
        LongRef l = new LongRef();
        WrapKey(session, mechanism, wrapping_key, key, null, l);
        byte[] result = new byte[l.val()];
        WrapKey(session, mechanism, wrapping_key, key, result, l);
        return resize(result, l.val());
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param unwrapping_key
     * @param wrapped_key
     * @param templ
     * @param key
     * @see C#UnwrapKey(int, CKM, int, byte[], CKA[], LongRef)
     * @see Native#C_UnwrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void UnwrapKey(int session, CKM mechanism, int unwrapping_key, byte[] wrapped_key, CKA[] templ, LongRef key) {
        int rv = C.UnwrapKey(session, mechanism, unwrapping_key, wrapped_key, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param unwrapping_key
     * @param wrapped_key
     * @param templ
     * @return
     * @see C#UnwrapKey(int, CKM, int, byte[], CKA[], LongRef)
     * @see Native#C_UnwrapKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int UnwrapKey(int session, CKM mechanism, int unwrapping_key, byte[] wrapped_key, CKA... templ) {
        LongRef result = new LongRef();
        UnwrapKey(session, mechanism, unwrapping_key, wrapped_key, templ, result);
        return result.val();
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param base_key
     * @param templ
     * @param key
     * @see C#DeriveKey(int, CKM, int, CKA[], LongRef)
     * @see Native#C_DeriveKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static void DeriveKey(int session, CKM mechanism, int base_key, CKA[] templ, LongRef key) {
        int rv = C.DeriveKey(session, mechanism, base_key, templ, key);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param mechanism
     * @param base_key
     * @param templ
     * @return
     * @see C#DeriveKey(int, CKM, int, CKA[], LongRef)
     * @see Native#C_DeriveKey(com.sun.jna.NativeLong, CKM, com.sun.jna.NativeLong, Template, com.sun.jna.NativeLong, LongRef)
     */
    public static int DeriveKey(int session, CKM mechanism, int base_key, CKA... templ) {
        LongRef key = new LongRef();
        DeriveKey(session, mechanism, base_key, templ, key);
        return key.val();
    }

    /**
     *
     * @param session
     * @param seed
     * @see C#SeedRandom(int, byte[])
     * @see Native#C_SeedRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void SeedRandom(int session, byte[] seed) {
        int rv = C.SeedRandom(session, seed);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param random_data
     * @see C#GenerateRandom(int, byte[])
     * @see Native#C_GenerateRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static void GenerateRandom(int session, byte[] random_data) {
        int rv = C.GenerateRandom(session, random_data);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
     * @param random_len
     * @return
     * @see C#GenerateRandom(int, byte[])
     * @see Native#C_GenerateRandom(com.sun.jna.NativeLong, byte[], com.sun.jna.NativeLong)
     */
    public static byte[] GenerateRandom(int session, int random_len) {
        byte[] result = new byte[random_len];
        GenerateRandom(session, result);
        return result;
    }

    /**
     *
     * @param session
     * @see C#GetFunctionStatus(int)
     * @see Native#C_GetFunctionStatus(com.sun.jna.NativeLong)
     */
    public static void GetFunctionStatus(int session) {
        int rv = C.GetFunctionStatus(session);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    /**
     *
     * @param session
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
