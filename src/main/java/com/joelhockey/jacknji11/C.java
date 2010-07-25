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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Low-level java interface that maps to {@link Native} cryptoki calls.
 *
 * jacknji11 provides 3 interfaces for calling cryptoki functions.
 * <ol>
 * <li>{@link com.joelhockey.jacknji11.Native} provides the lowest level
 * JNA direct mapping to the <code>'C_*'</code> functions.  There is little
 * reason why you would ever want to invoke it directly, but you can.
 * <li>{@link com.joelhockey.jacknji11.C} provides the exact same functions
 * as {@link com.joelhockey.jacknji11.Native} by calling through to the
 * corresponding native method.  The <code>'C_'</code> at the start of the
 * function name is removed since the <code>'C.'</code> when you call the
 * static methods of this class looks similar.  In addition to calling
 * the native methods, {@link com.joelhockey.jacknji11.C} provides logging
 * throug apache commons logging and handles some of the low-level JNA
 * plumbing such as updating some values if they are changed within the
 * native call on a function.  You can use this if you require fine-grain
 * control over something such as checking
 * {@link com.joelhockey.jacknji11.CKR} return codes.
 * <li>{@link com.joelhockey.jacknji11.CE} (<b>C</b>ryptoki
 * with <b>E</b>xceptions) provides the most user-friendly interface
 * and is the preferred interface to use.  It calls
 * related function(s) in {@link com.joelhockey.jacknji11.C},
 * and converts any non-zero return values into a
 * {@link com.joelhockey.jacknji11.CKRException}.  It automatically resizes
 * arrays and other helpful things.
 * </ol>
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class C {
    private static final Log log = LogFactory.getLog(C.class);

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
        return Initialize(args);
    }

    /**
     * Initialise Cryptoki with supplied args.
     * @see Native#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     */
    public static int Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        if (log.isDebugEnabled()) log.debug("> C_Initialize " + pInitArgs);
        int rv = Native.C_Initialize(pInitArgs);
        if (log.isDebugEnabled()) log.debug(String.format("< C_Initialize rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see Native#C_Finalize(Pointer)
     * @return {@link CKR} return code
     */
    public static int Finalize() {
        if (log.isDebugEnabled()) log.debug("> C_Finalize");
        int rv = Native.C_Finalize(null);
        if (log.isDebugEnabled()) log.debug(String.format("< C_Finalize rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @return {@link CKR} return code
     * @see Native#C_GetInfo(CK_INFO)
     */
    public static int GetInfo(CK_INFO info) {
        if (log.isDebugEnabled()) log.debug("> C_GetInfo");
        int rv = Native.C_GetInfo(info);
        info.read();
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetInfo rv=0x%08x{%s}\n%s", rv, CKR.I2S(rv), info));
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSlotList tokenPresent=%b count=%d", tokenPresent, count.val()));
        LongArray slotsRef = new LongArray(slotList);
        int rv = Native.C_GetSlotList(tokenPresent ? TRUE : FALSE, slotsRef, count);
        slotsRef.update();
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSlotList rv=0x%08x{%s} count=%d\n  %s", rv, CKR.I2S(rv), count.val(), Arrays.toString(slotList)));
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSlotInfo slotID=%d", slotID));
        int rv = Native.C_GetSlotInfo(new NativeLong(slotID), info);
        info.read();
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSlotInfo rv=0x%08x{%s}\n%s", rv, CKR.I2S(rv), info));
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetTokenInfo slotID=%d", slotID));
        int rv = Native.C_GetTokenInfo(new NativeLong(slotID), info);
        info.read();
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetTokenInfo rv=0x%08x{%s}\n%s", rv, CKR.I2S(rv), info));
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
        if (log.isDebugEnabled()) log.debug("> C_WaitForSlotEvent");
        int rv = Native.C_WaitForSlotEvent(new NativeLong(flags), slot, reserved);
        if (log.isDebugEnabled()) log.debug(String.format("< C_WaitForSlotEvent rv=0x%08x{%s} slot=%d", rv, CKR.I2S(rv), slot.val()));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetMechanismList slotID=%d count=%d", slotID, count.val()));
        LongArray longArray = new LongArray(mechanismList);
        int rv = Native.C_GetMechanismList(new NativeLong(slotID), longArray, count);
        longArray.update();
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetMechanismList rv=0x%08x{%s} count=%d", rv, CKR.I2S(rv), count.val()));
            if (mechanismList != null) {
                sb.append('\n');
                for (int m : mechanismList) {
                    sb.append(String.format("  0x%08x{%s}\n", m, CKM.I2S(m)));
                }
            }
            log.debug(sb);
        }
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetMechanismInfo slotID=%d type=0x%08x{%s}", slotID, type, CKM.I2S(type)));
        int rv = Native.C_GetMechanismInfo(new NativeLong(slotID), new NativeLong(type), info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetMechanismInfo rv=0x%08x{%s}\n%s", rv, CKR.I2S(rv), info));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_InitToken slotID=%d pin=*** label=%s", slotID, Buf.escstr(label32)));
        int rv = Native.C_InitToken(new NativeLong(slotID), pin, baLen(pin), label32);
        if (log.isDebugEnabled()) log.debug(String.format("< C_InitToken rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @return {@link CKR} return code
     * @see Native#C_InitPIN(NativeLong, byte[], NativeLong)
     */
    public static int InitPIN(int session, byte[] pin) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_InitPIN session=0x%08x pin=***", session));
        int rv = Native.C_InitPIN(new NativeLong(session), pin, baLen(pin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_InitPIN rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_SetPIN session=0x%08x oldPin=*** newPin=***", session));
        int rv = Native.C_SetPIN(new NativeLong(session), oldPin, baLen(oldPin), newPin, baLen(newPin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetPIN rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_OpenSession slotID=%d flags=0x%08x{%s} application=%s notify=%s", slotID, flags, CK_SESSION_INFO.f2s(flags), application, notify));
        int rv = Native.C_OpenSession(new NativeLong(slotID), new NativeLong(flags), application, notify, session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_OpenSession rv=0x%08x{%s} session=0x%08x", rv, CKR.I2S(rv), session.val()));
        return rv;
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_CloseSession(NativeLong)
     */
    public static int CloseSession(int session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_CloseSession session=0x%08x", session));
        int rv = Native.C_CloseSession(new NativeLong(session));
        if (log.isDebugEnabled()) log.debug(String.format("< C_CloseSession rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see Native#C_CloseAllSessions(NativeLong)
     */
    public static int CloseAllSessions(int slotID) {
        if (log.isDebugEnabled()) log.debug("> C_CloseAllSessions");
        int rv = Native.C_CloseAllSessions(new NativeLong(slotID));
        if (log.isDebugEnabled()) log.debug(String.format("< C_CloseAllSessions rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @return {@link CKR} return code
     * @see Native#C_GetSessionInfo(NativeLong, CK_SESSION_INFO)
     */
    public static int GetSessionInfo(int session, CK_SESSION_INFO info) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSessionInfo session=0x%08x", session));
        int rv = Native.C_GetSessionInfo(new NativeLong(session), info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSessionInfo rv=0x%08x{%s}\n%s", rv, CKR.I2S(rv), info));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetOperationState session=0x%08x operationStateLen=%d", session, operationStateLen.val()));
        int rv = Native.C_GetOperationState(new NativeLong(session), operationState, operationStateLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetOperationState rv=0x%08x{%s}\n  operationState (len=%d):", rv, CKR.I2S(rv), operationStateLen.val()));
            if (operationState != null) {
                Hex.dump(sb, operationState, 0, operationStateLen.val(), "  ", 32);
            }
            log.debug(sb);
        }
        return rv;
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

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format(
                    "> C_SetOperationState session=0x%08x encryptionKey=0x%08x authenticationKey=0x%08x\n  operationState (len=%d):",
                    session, encryptionKey, authenticationKey, operationState.length));
            Hex.dump(sb, operationState, 0, operationState.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_SetOperationState(new NativeLong(session), operationState, baLen(operationState),
                new NativeLong(encryptionKey), new NativeLong(authenticationKey));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetOperationState rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_Login session=0x%08x userType=0x%08x{%s} pin=***", session, userType, CKU.I2S(userType)));
        int rv = Native.C_Login(new NativeLong(session), new NativeLong(userType), pin, baLen(pin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_Login rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_Logout(NativeLong)
     */
    public static int Logout(int session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_Logout session=0x%08x", session));
        int rv = Native.C_Logout(new NativeLong(session));
        if (log.isDebugEnabled()) log.debug(String.format("< C_Logout rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_CreateObject session=0x%08x\n", session));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_CreateObject(new NativeLong(session), t, t.length(), object);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CreateObject rv=0x%08x{%s} object=0x%08x", rv, CKR.I2S(rv), object.val()));
        return rv;
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_CopyObject session=0x%08x object=0x%08x\n", session, object));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_CopyObject(new NativeLong(session), new NativeLong(object), t, t.length(), newObject);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CopyObject rv=0x%08x{%s} newObject=0x%08x", rv, CKR.I2S(rv), newObject.val()));
        return rv;
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @return {@link CKR} return code
     * @see Native#C_DestroyObject(NativeLong, NativeLong)
     */
    public static int DestroyObject(int session, int object) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DestroyObject session=0x%08x object=0x%08x", session, object));
        int rv = Native.C_DestroyObject(new NativeLong(session), new NativeLong(object));
        if (log.isDebugEnabled()) log.debug(String.format("< C_DestroyObject rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetObjectSize session=0x%08x object=0x%08x", session, object));
        int rv = Native.C_GetObjectSize(new NativeLong(session), new NativeLong(object), size);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetObjectSize rv=0x%08x{%s} size=%d", rv, CKR.I2S(rv), size.val()));
        return rv;
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GetAttributeValue session=0x%08x object=0x%08x\n", session, object));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_GetAttributeValue(new NativeLong(session), new NativeLong(object), t, t.length());
        t.update();
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetAttributeValue rv=0x%08x{%s}\n", rv, CKR.I2S(rv)));
            t.dump(sb);
            log.debug(sb);
        }
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SetAttributeValue session=0x%08x object=0x%08x\n", session, object));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_SetAttributeValue(new NativeLong(session), new NativeLong(object), t, t.length());
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetAttributeValue rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Initialises a search for token and sesion objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsInit(NativeLong, Template, NativeLong)
     */
    public static int FindObjectsInit(int session, CKA[] templ) {
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_FindObjectsInit session=0x%08x\n", session));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_FindObjectsInit(new NativeLong(session), t, t.length());
        if (log.isDebugEnabled()) log.debug(String.format("< C_FindObjectsInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_FindObjects session=0x%08x maxObjectCount=%d", session, found != null ? found.length : 0));
        int rv = Native.C_FindObjects(new NativeLong(session), longArray,
                new NativeLong(found == null ? 0 : found.length), objectCount);
        longArray.update();
        if (log.isDebugEnabled()) {
            int l = objectCount.val();
            // only debug found[0:l]
            int[] toDisplay = found;
            if (l < found.length) {
                toDisplay = new int[l];
                System.arraycopy(found, 0, toDisplay, 0, l);
            }
            log.debug(String.format("< C_FindObjects rv=0x%08x{%s} objectCount=%d\n  %s", rv, CKR.I2S(rv), objectCount.val(), Arrays.toString(toDisplay)));
        }
        return rv;
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see Native#C_FindObjectsFinal(NativeLong)
     */
    public static int FindObjectsFinal(int session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_FindObjectsFinal session=0x%08x", session));
        int rv = Native.C_FindObjectsFinal(new NativeLong(session));
        if (log.isDebugEnabled()) log.debug(String.format("< C_FindObjectsFinal rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_EncryptInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_EncryptInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_EncryptInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Encrypt session=0x%08x encryptedDataLen=%d data\n  (len=%d):", session, encryptedDataLen.val(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_Encrypt(new NativeLong(session), data, baLen(data), encryptedData, encryptedDataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Encrypt rv=0x%08x{%s}\n  encryptedData (len=%d):", rv, CKR.I2S(rv), encryptedDataLen.val()));
            Hex.dump(sb, encryptedData, 0, encryptedDataLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_EncryptUpdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):", session, encryptedPartLen.val(), part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_EncryptUpdate(new NativeLong(session), part, baLen(part), encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_EncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):", rv, CKR.I2S(rv), encryptedPartLen.val()));
            Hex.dump(sb, encryptedPart, 0, encryptedPartLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_EncryptFinal session=0x%08x lastEncryptedPartLen=%d", session, lastEncryptedPartLen.val()));
        int rv = Native.C_EncryptFinal(new NativeLong(session), lastEncryptedPart, lastEncryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_EncryptFinal rv=0x%08x{%s}\n  lastEncryptedPart (len=%d):", rv, CKR.I2S(rv), lastEncryptedPartLen.val()));
            Hex.dump(sb, lastEncryptedPart, 0, lastEncryptedPartLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_DecryptInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_DecryptInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_DecryptInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Decrypt session=0x%08x dataLen=%d\n encryptedData (len=%d):", session, dataLen.val(), encryptedData.length));
            Hex.dump(sb, encryptedData, 0, encryptedData.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_Decrypt(new NativeLong(session), encryptedData, baLen(encryptedData), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Decrypt rv=0x%08x{%s}\n  data (len=%d):", rv, CKR.I2S(rv), dataLen.val()));
            Hex.dump(sb, data, 0, dataLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptUpdate session=0x%08x dataLen=%d\n  encryptedPart (len=%d):", session, dataLen.val(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_DecryptUpdate(new NativeLong(session), encryptedPart, baLen(encryptedPart), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptUpdate rv=0x%08x{%s}\n  data (len=%d):", rv, CKR.I2S(rv), dataLen.val()));
            Hex.dump(sb, data, 0, dataLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_DecryptFinal session=0x%08x lastPartLen=%d", session, lastPartLen.val()));
        int rv = Native.C_DecryptFinal(new NativeLong(session), lastPart, lastPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptFinal rv=0x%08x{%s}\n  lastPart (len=%d):", rv, CKR.I2S(rv), lastPartLen.val()));
            Hex.dump(sb, lastPart, 0, lastPartLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @return {@link CKR} return code
     * @see Native#C_DigestInit(NativeLong, CKM)
     */
    public static int DigestInit(int session, CKM mechanism) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestInit session=0x%08x\n  %s", session, mechanism));
        int rv = Native.C_DigestInit(new NativeLong(session), mechanism);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Digest session=0x%08x digestLen=%d\n  data (len=%d):", session, digestLen.val(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_Digest(new NativeLong(session), data, baLen(data), digest, digestLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Digest rv=0x%08x{%s}\n  digest (len=%d):", rv, CKR.I2S(rv), digestLen.val()));
            Hex.dump(sb, digest, 0, digestLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @return {@link CKR} return code
     * @see Native#C_DigestUpdate(NativeLong, byte[], NativeLong)
     */
    public static int DigestUpdate(int session, byte[] part) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DigestUpdate session=0x%08x\n  part (len=%d):", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_DigestUpdate(new NativeLong(session), part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestUpdate rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestKey session=0x%08x key=0x%08x", session, key));
        int rv = Native.C_DigestKey(new NativeLong(session), new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestKey rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestFial session=0x%08x digestLen=%d", session, digestLen.val()));
        int rv = Native.C_DigestFinal(new NativeLong(session), digest, digestLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DigestFinal rv=0x%08x{%s}\n  digest (len=%d):", rv, CKR.I2S(rv), digestLen.val()));
            Hex.dump(sb, digest, 0, digestLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_SignInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Sign session=0x%08x signatureLen=%d\n  data (len=%d):", session, signatureLen.val(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_Sign(new NativeLong(session), data, baLen(data), signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Sign rv=0x%08x{%s}\n  signature (len=%d):", rv, CKR.I2S(rv), signatureLen.val()));
            Hex.dump(sb, signature, 0, signatureLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignUpdate session=0x%08x\n  part (len=%d):", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_SignUpdate(new NativeLong(session), part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignUpdate rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignFinal session=0x%08x signatureLen=%d", session, signatureLen.val()));
        int rv = Native.C_SignFinal(new NativeLong(session), signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignFinal rv=0x%08x{%s}\n  signature (len=%d):", rv, CKR.I2S(rv), signatureLen.val()));
            Hex.dump(sb, signature, 0, signatureLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignRecoverInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_SignRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignRecoverInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignRecover session=0x%08x signatureLen=%d\n  data (len=%d):", session, signatureLen.val(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_SignRecover(new NativeLong(session), data, baLen(data), signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignRecover rv=0x%08x{%s}\n  signature (len=%d):", rv, CKR.I2S(rv), signatureLen.val()));
            Hex.dump(sb, signature, 0, signatureLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_VerifyInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_VerifyInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Verify session=0x%08x\n  data (len=%d):", session, data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32);
            sb.append("\n  signature (len=%d):");
            Hex.dump(sb, signature, 0, signature.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_Verify(new NativeLong(session), data, baLen(data), signature, baLen(signature));
        log.debug(String.format("< C_Verify rv=0x%08x{%s} ", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyUpdate session=0x%08x\n  part (len=%d):", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_VerifyUpdate(new NativeLong(session), part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyUpdate rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return {@link CKR} return code
     * @see Native#C_VerifyFinal(NativeLong, byte[], NativeLong)
     */
    public static int VerifyFinal(int session, byte[] signature) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyFinal session=0x%08x\n  signature (len=%d):", session, signature.length));
            Hex.dump(sb, signature, 0, signature.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_VerifyFinal(new NativeLong(session), signature, baLen(signature));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyFinal rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_VerifyRecoverInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_VerifyRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyRecoverInit rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyRecover session=0x%08x dataLen=%d\n  signature (len=%d):", session, dataLen.val(), signature.length));
            Hex.dump(sb, signature, 0, signature.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_VerifyRecover(new NativeLong(session), signature, baLen(signature), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_VerifyRecover rv=0x%08x{%s}\n  data (len=%d):", rv, CKR.I2S(rv), dataLen.val()));
            Hex.dump(sb, data, 0, dataLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
    public static int DigestEncryptUpdate(int session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DigestEncryptUpdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):", session, encryptedPartLen.val(), part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_DigestEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DigestEncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):", rv, CKR.I2S(rv), encryptedPartLen.val()));
            Hex.dump(sb, encryptedPart, 0, encryptedPartLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptDigestUpdate session=0x%08x partLen=%d\n  encryptedPart (len=%d):", session, partLen.val(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_DecryptDigestUpdate(new NativeLong(session),
                encryptedPart, baLen(encryptedPart), part, partLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptDigestUpdate rv=0x%08x{%s}\n  part (len=%d):", rv, CKR.I2S(rv), partLen.val()));
            Hex.dump(sb, part, 0, partLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignEncryptUdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):", session, encryptedPartLen.val(), part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_SignEncryptUpdate(new NativeLong(session), part, baLen(part),
                encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignEncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):", rv, CKR.I2S(rv), encryptedPartLen.val()));
            Hex.dump(sb, encryptedPart, 0, encryptedPartLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
    }

    /**
     * Continues a multiple-part decryption and verify operation.
     * @param session the session's handle
     * @param encryptedPart ciphertext
     * @param part gets plaintext
     * @param partLen gets p-text length
     * @return {@link CKR} return code
     * @see Native#C_DecryptVerifyUpdate(NativeLong, byte[], NativeLong, byte[], LongRef)
     */
    public static int DecryptVerifyUpdate(int session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptVerifyUpdate session=0x%08x partLen=%d\n  encryptedPart (len=%d):", session, partLen.val(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_DecryptVerifyUpdate(new NativeLong(session),
                encryptedPart, baLen(encryptedPart), part, partLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptVerifyUpdate rv=0x%08x{%s}\n  part (len=%d):", rv, CKR.I2S(rv), partLen.val()));
            Hex.dump(sb, part, 0, partLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GenerateKey session=0x%08x %s\n", session, mechanism));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_GenerateKey(new NativeLong(session), mechanism, t, t.length(), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GenerateKey rv=0x%08x{%s} key=0x%08x", rv, CKR.I2S(rv), key.val()));
        return rv;
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
        Template pubT = new Template(publicKeyTemplate);
        Template privT = new Template(privateKeyTemplate);

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GenerateKeyPair session=0x%08x\n  %s", session, mechanism));
            sb.append("\n  publicKeyTemplate:\n");
            pubT.dump(sb);
            sb.append("\n  privateKeyTemplate:\n");
            privT.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_GenerateKeyPair(new NativeLong(session), mechanism,
                pubT, pubT.length(), privT, privT.length(), publicKey, privateKey);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GenerateKeyPair rv=0x%08x{%s} publicKey=0x%08x privateKey=0x%08x", rv, CKR.I2S(rv), publicKey.val(), privateKey.val()));
        return rv;
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

        if (log.isDebugEnabled()) log.debug(String.format("> C_WrapKey session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        int rv = Native.C_WrapKey(new NativeLong(session), mechanism, new NativeLong(wrappingKey),
                new NativeLong(key), wrappedKey, wrappedKeyLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_WrapKey rv=0x%08x{%s}\n  wrappedKey (len=%d):", rv, CKR.I2S(rv), wrappedKeyLen.val()));
            Hex.dump(sb, wrappedKey, 0, wrappedKeyLen.val(), "  ", 32);
            log.debug(sb);
        }
        return rv;
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

        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_UnwrapKey session=0x%08x unwrappingKey=0x%08x %s\n  wrappedKey (len=%d):", session, unwrappingKey, mechanism, wrappedKey.length));
            Hex.dump(sb, wrappedKey, 0, wrappedKey.length, "  ", 32);
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_UnwrapKey(new NativeLong(session), mechanism, new NativeLong(unwrappingKey),
                wrappedKey, baLen(wrappedKey), t, t.length(), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_UnwrapKey rv=0x%08x{%s} key=0x%08x", rv, CKR.I2S(rv), key.val()));
        return rv;
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
        Template t = new Template(templ);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DeriveKey session=0x%08x baseKey=0x%08x %s\n", session, baseKey, mechanism));
            t.dump(sb);
            log.debug(sb);
        }
        int rv = Native.C_DeriveKey(new NativeLong(session), mechanism, new NativeLong(baseKey), t, t.length(), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DeriveKey rv=0x%08x{%s} key=0x%08x", rv, CKR.I2S(rv), key.val()));
        return rv;
    }

    /**
     * Mixes additional seed material into the token’s random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @return {@link CKR} return code
     * @see Native#C_SeedRandom(NativeLong, byte[], NativeLong)
     */
    public static int SeedRandom(int session, byte[] seed) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SeedRandom session=0x%08x\n  seed (len=%d):", session, seed.length));
            Hex.dump(sb, seed, 0, seed.length, "  ", 32);
            log.debug(sb);
        }
        int rv = Native.C_SeedRandom(new NativeLong(session), seed, baLen(seed));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SeedRandom rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @return {@link CKR} return code
     * @see Native#C_GenerateRandom(NativeLong, byte[], NativeLong)
     */
    public static int GenerateRandom(int session, byte[] randomData) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GenerateRandom session=0x%08x randomLen=%d", session, randomData.length));
        int rv = Native.C_GenerateRandom(new NativeLong(session), randomData, baLen(randomData));
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GenerateRandom rv=0x%08x{%s}\n  randomData (len=%d):", rv, CKR.I2S(rv), randomData.length));
            Hex.dump(sb, randomData, 0, randomData.length, "  ", 32);
            log.debug(sb);
        }
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetFunctionStatus session=0x%08x", session));
        int rv = Native.C_GetFunctionStatus(new NativeLong(session));
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetFunctionStatus rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
        if (log.isDebugEnabled()) log.debug(String.format("> C_CancelFunction session=0x%08x", session));
        int rv = Native.C_CancelFunction(new NativeLong(session));
        if (log.isDebugEnabled()) log.debug(String.format("< C_CancelFunction rv=0x%08x{%s}", rv, CKR.I2S(rv)));
        return rv;
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
     * Helper method.  Adds all public static final int fields in c to map, mapping field value to name.
     * @param c class
     * @return map of field value:name
     */
    public static Map<Integer, String> createI2SMap(Class c) {
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
        StringBuilder sb = new StringBuilder();
        String sep = "";
        for (int i = 31; i >= 0; i--) {
            if ((flags & (1 << i)) != 0) {
                sb.append(sep);
                sb.append(C.i2s(i2s, "CKF", 1 << i));
                sep = "|";
            }
        }
        return sb.toString();
    }
}
