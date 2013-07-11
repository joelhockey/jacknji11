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
 */
public class C {
    private static final Log log = LogFactory.getLog(C.class);

    public static NativeProvider NATIVE = new JNA();

    private static final NativePointer NULL = new NativePointer(0);

    /**
     * Initialise Cryptoki with null mutexes, and CKF_OS_LOCKING_OK flag set.
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     */
    public static long Initialize() {
        CK_C_INITIALIZE_ARGS args = new CK_C_INITIALIZE_ARGS(null, null, null, null,
                CK_C_INITIALIZE_ARGS.CKF_OS_LOCKING_OK);
        return Initialize(args);
    }

    /**
     * Initialise Cryptoki with supplied args.
     * @see NativeProvider#C_Initialize(CK_C_INITIALIZE_ARGS)
     * @return {@link CKR} return code
     */
    public static long Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        if (log.isDebugEnabled()) log.debug("> C_Initialize " + pInitArgs);
        long rv =NATIVE.C_Initialize(pInitArgs);
        if (log.isDebugEnabled()) log.debug(String.format("< C_Initialize rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Called to indicate that an application is finished with the Cryptoki library.
     * @see NativeProvider#C_Finalize(Pointer)
     * @return {@link CKR} return code
     */
    public static long Finalize() {
        if (log.isDebugEnabled()) log.debug("> C_Finalize");
        long rv =NATIVE.C_Finalize(NULL);
        if (log.isDebugEnabled()) log.debug(String.format("< C_Finalize rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Returns general information about Cryptoki.
     * @param info location that receives information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public static long GetInfo(CK_INFO info) {
        if (log.isDebugEnabled()) log.debug("> C_GetInfo");
        long rv =NATIVE.C_GetInfo(info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetInfo rv=0x%08x{%s}\n%s", rv, CKR.L2S(rv), info));
        return rv;
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param slotList receives array of slot IDs
     * @param count receives the number of slots
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotList(byte, LongArray, LongRef)
     */
    public static long GetSlotList(boolean tokenPresent, long[] slotList, LongRef count) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSlotList tokenPresent=%b count=%d", tokenPresent, count.value()));
        long rv =NATIVE.C_GetSlotList(tokenPresent, slotList, count);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSlotList rv=0x%08x{%s} count=%d\n  %s", rv, CKR.L2S(rv), count.value(), Arrays.toString(slotList)));
        return rv;
    }

    /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param info receives the slot information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_INFO)
     */
    public static long GetSlotInfo(long slotID, CK_SLOT_INFO info) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSlotInfo slotID=%d", slotID));
        long rv =NATIVE.C_GetSlotInfo(slotID, info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSlotInfo rv=0x%08x{%s}\n%s", rv, CKR.L2S(rv), info));
        return rv;
    }

    /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param info receives the token information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_INFO)
     */
    public static long GetTokenInfo(long slotID, CK_TOKEN_INFO info) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetTokenInfo slotID=%d", slotID));
        long rv =NATIVE.C_GetTokenInfo(slotID, info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetTokenInfo rv=0x%08x{%s}\n%s", rv, CKR.L2S(rv), info));
        return rv;
    }

    /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param slot location that receives the slot ID
     * @param reserved reserved.  Should be null
     * @return {@link CKR} return code
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, Pointer)
     */
    public static long WaitForSlotEvent(long flags, LongRef slot, NativePointer reserved) {
        if (log.isDebugEnabled()) log.debug("> C_WaitForSlotEvent");
        long rv =NATIVE.C_WaitForSlotEvent(flags, slot, reserved != null ? reserved : NULL);
        if (log.isDebugEnabled()) log.debug(String.format("< C_WaitForSlotEvent rv=0x%08x{%s} slot=%d", rv, CKR.L2S(rv), slot.value()));
        return rv;
    }

    /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param mechanismList gets mechanism array
     * @param count gets # of mechanisms
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetMechanismList(long, LongArray, LongRef)
     */
    public static long GetMechanismList(long slotID, long[] mechanismList, LongRef count) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetMechanismList slotID=%d count=%d", slotID, count.value()));
        long rv =NATIVE.C_GetMechanismList(slotID, mechanismList, count);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetMechanismList rv=0x%08x{%s} count=%d", rv, CKR.L2S(rv), count.value()));
            if (mechanismList != null) {
                sb.append('\n');
                for (long m : mechanismList) {
                    sb.append(String.format("  0x%08x{%s}\n", m, CKM.L2S(m)));
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
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public static long GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO info) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetMechanismInfo slotID=%d type=0x%08x{%s}", slotID, type, CKM.L2S(type)));
        long rv =NATIVE.C_GetMechanismInfo(slotID, type, info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetMechanismInfo rv=0x%08x{%s}\n%s", rv, CKR.L2S(rv), info));
        return rv;
    }

    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pin the SO's intital PIN
     * @param label 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     */
    public static long InitToken(long slotID, byte[] pin, byte[] label) {
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
        long rv =NATIVE.C_InitToken(slotID, pin, baLen(pin), label32);
        if (log.isDebugEnabled()) log.debug(String.format("< C_InitToken rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Initialise normal user with PIN.
     * @param session the session's handle
     * @param pin the normal user's PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    public static long InitPIN(long session, byte[] pin) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_InitPIN session=0x%08x pin=***", session));
        long rv =NATIVE.C_InitPIN(session, pin, baLen(pin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_InitPIN rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Change PIN.
     * @param session the session's handle
     * @param oldPin old PIN
     * @param newPin new PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    public static long SetPIN(long session, byte[] oldPin, byte[] newPin) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_SetPIN session=0x%08x oldPin=*** newPin=***", session));
        long rv =NATIVE.C_SetPIN(session, oldPin, baLen(oldPin), newPin, baLen(newPin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetPIN rv=0x%08x{%s}", rv, CKR.L2S(rv)));
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
     * @see NativeProvider#C_OpenSession(long, long, Pointer, CK_NOTIFY, LongRef)
     */
    public static long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify, LongRef session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_OpenSession slotID=%d flags=0x%08x{%s} application=%s notify=%s", slotID, flags, CK_SESSION_INFO.f2s(flags), application, notify));
        long rv =NATIVE.C_OpenSession(slotID, flags, application != null ? application : NULL, notify, session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_OpenSession rv=0x%08x{%s} session=0x%08x", rv, CKR.L2S(rv), session.value()));
        return rv;
    }

    /**
     * Closes a session between an application and a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseSession(long)
     */
    public static long CloseSession(long session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_CloseSession session=0x%08x", session));
        long rv =NATIVE.C_CloseSession(session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CloseSession rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public static long CloseAllSessions(long slotID) {
        if (log.isDebugEnabled()) log.debug("> C_CloseAllSessions");
        long rv =NATIVE.C_CloseAllSessions(slotID);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CloseAllSessions rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Obtains information about the session.
     * @param session the session's handle
     * @param info receives session info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public static long GetSessionInfo(long session, CK_SESSION_INFO info) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetSessionInfo session=0x%08x", session));
        long rv =NATIVE.C_GetSessionInfo(session, info);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetSessionInfo rv=0x%08x{%s}\n%s", rv, CKR.L2S(rv), info));
        return rv;
    }

    /**
     * Obtains the state of the cryptographic operation.
     * @param session the session's handle
     * @param operationState gets state
     * @param operationStateLen gets state length
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public static long GetOperationState(long session, byte[] operationState, LongRef operationStateLen) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetOperationState session=0x%08x operationStateLen=%d", session, operationStateLen.value()));
        long rv =NATIVE.C_GetOperationState(session, operationState, operationStateLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetOperationState rv=0x%08x{%s}\n  operationState (len=%d):\n", rv, CKR.L2S(rv), operationStateLen.value()));
            if (operationState != null) {
                Hex.dump(sb, operationState, 0, (int) operationStateLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     */
    public static long SetOperationState(long session, byte[] operationState,
            long encryptionKey, long authenticationKey) {

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format(
                    "> C_SetOperationState session=0x%08x encryptionKey=0x%08x authenticationKey=0x%08x\n  operationState (len=%d):\n",
                    session, encryptionKey, authenticationKey, operationState.length));
            Hex.dump(sb, operationState, 0, operationState.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_SetOperationState(session, operationState, baLen(operationState),
                encryptionKey, authenticationKey);
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetOperationState rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Logs a user into a token.
     * @param session the session's handle
     * @param userType the user type from {@link CKU}
     * @param pin the user's PIN
     * @return {@link CKR} return code
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public static long Login(long session, long userType, byte[] pin) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_Login session=0x%08x userType=0x%08x{%s} pin=***", session, userType, CKU.L2S(userType)));
        long rv =NATIVE.C_Login(session, userType, pin, baLen(pin));
        if (log.isDebugEnabled()) log.debug(String.format("< C_Login rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Logs a user out from a token.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_Logout(long)
     */
    public static long Logout(long session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_Logout session=0x%08x", session));
        long rv =NATIVE.C_Logout(session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_Logout rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Creates a new object.
     * @param session the session's handle
     * @param templ the objects template
     * @param object gets new object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CreateObject(long, Template, long, LongRef)
     */
    public static long CreateObject(long session, CKA[] templ, LongRef object) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_CreateObject session=0x%08x\n", session));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_CreateObject(session, templ, templLen(templ), object);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CreateObject rv=0x%08x{%s} object=0x%08x", rv, CKR.L2S(rv), object.value()));
        return rv;
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param session the session's handle
     * @param object the object's handle
     * @param templ template for new object
     * @param newObject receives handle of copy
     * @return {@link CKR} return code
     * @see NativeProvider#C_CopyObject(long, long, Template, long, LongRef)
     */
    public static long CopyObject(long session, long object, CKA[] templ, LongRef newObject) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_CopyObject session=0x%08x object=0x%08x\n", session, object));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_CopyObject(session, object, templ, templLen(templ), newObject);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CopyObject rv=0x%08x{%s} newObject=0x%08x", rv, CKR.L2S(rv), newObject.value()));
        return rv;
    }

    /**
     * Destroys an object.
     * @param session the session's handle
     * @param object the object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    public static long DestroyObject(long session, long object) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DestroyObject session=0x%08x object=0x%08x", session, object));
        long rv =NATIVE.C_DestroyObject(session, object);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DestroyObject rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Gets the size of an object in bytes.
     * @param session the session's handle
     * @param object the object's handle
     * @param size receives the size of object
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public static long GetObjectSize(long session, long object, LongRef size) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetObjectSize session=0x%08x object=0x%08x", session, object));
        long rv =NATIVE.C_GetObjectSize(session, object, size);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetObjectSize rv=0x%08x{%s} size=%d", rv, CKR.L2S(rv), size.value()));
        return rv;
    }

    /**
     * Obtains the value of one or more object attributes.
     * @param session the session's handle
     * @param object the objects's handle
     * @param templ specifies attributes, gets values
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetAttributeValue(long, long, Template, long)
     */
    public static long GetAttributeValue(long session, long object, CKA[] templ) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GetAttributeValue session=0x%08x object=0x%08x\n", session, object));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_GetAttributeValue(session, object, templ, templLen(templ));
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GetAttributeValue rv=0x%08x{%s}\n", rv, CKR.L2S(rv)));
            dumpTemplate(sb, templ);
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
     * @see NativeProvider#C_SetAttributeValue(long, long, Template, long)
     */
    public static long SetAttributeValue(long session, long object, CKA[] templ) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SetAttributeValue session=0x%08x object=0x%08x\n", session, object));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_SetAttributeValue(session, object, templ, templLen(templ));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SetAttributeValue rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Initialises a search for token and sesion objects that match a template.
     * @param session the session's handle
     * @param templ attribute values to match
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsInit(long, Template, long)
     */
    public static long FindObjectsInit(long session, CKA[] templ) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_FindObjectsInit session=0x%08x\n", session));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_FindObjectsInit(session, templ, templLen(templ));
        if (log.isDebugEnabled()) log.debug(String.format("< C_FindObjectsInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param session the session's handle
     * @param found gets object handles
     * @param objectCount number of object handles returned
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjects(long, LongArray, long, LongRef)
     */
    public static long FindObjects(long session, long[] found, LongRef objectCount) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_FindObjects session=0x%08x maxObjectCount=%d", session, found != null ? found.length : 0));
        long rv = NATIVE.C_FindObjects(session, found, found == null ? 0 : found.length, objectCount);
        if (log.isDebugEnabled()) {
            int l = (int) objectCount.value();
            // only debug found[0:l]
            long[] toDisplay = found;
            if (l < found.length) {
                toDisplay = new long[l];
                System.arraycopy(found, 0, toDisplay, 0, l);
            }
            log.debug(String.format("< C_FindObjects rv=0x%08x{%s} objectCount=%d\n  %s", rv, CKR.L2S(rv), objectCount.value(), Arrays.toString(toDisplay)));
        }
        return rv;
    }

    /**
     * Finishes a search for token and session objects.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public static long FindObjectsFinal(long session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_FindObjectsFinal session=0x%08x", session));
        long rv =NATIVE.C_FindObjectsFinal(session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_FindObjectsFinal rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Initialises an encryption operation.
     * @param session the session's handle
     * @param mechanism the encryption mechanism
     * @param key handle of encryption key
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    public static long EncryptInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_EncryptInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_EncryptInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_EncryptInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Encrypts single-part data.
     * @param session the session's handle
     * @param data the plaintext data
     * @param encryptedData gets ciphertext
     * @param encryptedDataLen gets c-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public static long Encrypt(long session, byte[] data, byte[] encryptedData, LongRef encryptedDataLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Encrypt session=0x%08x encryptedDataLen=%d data\n  (len=%d):\n", session, encryptedDataLen.value(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_Encrypt(session, data, baLen(data), encryptedData, encryptedDataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Encrypt rv=0x%08x{%s}\n  encryptedData (len=%d):\n", rv, CKR.L2S(rv), encryptedDataLen.value()));
            Hex.dump(sb, encryptedData, 0, (int) encryptedDataLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static long EncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_EncryptUpdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):\n", session, encryptedPartLen.value(), part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_EncryptUpdate(session, part, baLen(part), encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_EncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):\n", rv, CKR.L2S(rv), encryptedPartLen.value()));
            Hex.dump(sb, encryptedPart, 0, (int) encryptedPartLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public static long EncryptFinal(long session, byte[] lastEncryptedPart, LongRef lastEncryptedPartLen) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_EncryptFinal session=0x%08x lastEncryptedPartLen=%d", session, lastEncryptedPartLen.value()));
        long rv =NATIVE.C_EncryptFinal(session, lastEncryptedPart, lastEncryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_EncryptFinal rv=0x%08x{%s}\n  lastEncryptedPart (len=%d):\n", rv, CKR.L2S(rv), lastEncryptedPartLen.value()));
            Hex.dump(sb, lastEncryptedPart, 0, (int) lastEncryptedPartLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    public static long DecryptInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DecryptInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_DecryptInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DecryptInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param session the session's handle
     * @param encryptedData cipertext
     * @param data gets plaintext
     * @param dataLen gets p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public static long Decrypt(long session, byte[] encryptedData, byte[] data, LongRef dataLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Decrypt session=0x%08x dataLen=%d\n encryptedData (len=%d):\n", session, dataLen.value(), encryptedData.length));
            Hex.dump(sb, encryptedData, 0, encryptedData.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_Decrypt(session, encryptedData, baLen(encryptedData), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Decrypt rv=0x%08x{%s}\n  data (len=%d):\n", rv, CKR.L2S(rv), dataLen.value()));
            Hex.dump(sb, data, 0, (int) dataLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static long DecryptUpdate(long session, byte[] encryptedPart, byte[] data, LongRef dataLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptUpdate session=0x%08x dataLen=%d\n  encryptedPart (len=%d):\n", session, dataLen.value(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_DecryptUpdate(session, encryptedPart, baLen(encryptedPart), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptUpdate rv=0x%08x{%s}\n  data (len=%d):\n", rv, CKR.L2S(rv), dataLen.value()));
            Hex.dump(sb, data, 0, (int) dataLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public static long DecryptFinal(long session, byte[] lastPart, LongRef lastPartLen) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DecryptFinal session=0x%08x lastPartLen=%d", session, lastPartLen.value()));
        long rv =NATIVE.C_DecryptFinal(session, lastPart, lastPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptFinal rv=0x%08x{%s}\n  lastPart (len=%d):\n", rv, CKR.L2S(rv), lastPartLen.value()));
            Hex.dump(sb, lastPart, 0, (int) lastPartLen.value(), "  ", 32, false);
            log.debug(sb);
        }
        return rv;
    }

    /**
     * Initialises a message-digesting operation.
     * @param session the session's handle
     * @param mechanism the digesting mechanism
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    public static long DigestInit(long session, CKM mechanism) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestInit session=0x%08x\n  %s", session, mechanism));
        long rv =NATIVE.C_DigestInit(session, mechanism);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Digests data in a single part.
     * @param session the session's handle
     * @param data data to be digested
     * @param digest gets the message digest
     * @param digestLen gets digest length
     * @return {@link CKR} return code
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public static long Digest(long session, byte[] data, byte[] digest, LongRef digestLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Digest session=0x%08x digestLen=%d\n  data (len=%d):\n", session, digestLen.value(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_Digest(session, data, baLen(data), digest, digestLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Digest rv=0x%08x{%s}\n  digest (len=%d):\n", rv, CKR.L2S(rv), digestLen.value()));
            Hex.dump(sb, digest, 0, (int) digestLen.value(), "  ", 32, false);
            log.debug(sb);
        }
        return rv;
    }

    /**
     * Continues a multiple-part message-digesting.
     * @param session the session's handle
     * @param part data to be digested
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public static long DigestUpdate(long session, byte[] part) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DigestUpdate session=0x%08x\n  part (len=%d):\n", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_DigestUpdate(session, part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestUpdate rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param session the session's handle
     * @param key secret key to digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestKey(long, long)
     */
    public static long DigestKey(long session, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestKey session=0x%08x key=0x%08x", session, key));
        long rv =NATIVE.C_DigestKey(session, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DigestKey rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Finishes a multiple-part message-digesting operation.
     * @param session the session's handle
     * @param digest gets the message digest
     * @param digestLen gets byte count of digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public static long DigestFinal(long session, byte[] digest, LongRef digestLen) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_DigestFial session=0x%08x digestLen=%d", session, digestLen.value()));
        long rv =NATIVE.C_DigestFinal(session, digest, digestLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DigestFinal rv=0x%08x{%s}\n  digest (len=%d):\n", rv, CKR.L2S(rv), digestLen.value()));
            Hex.dump(sb, digest, 0, (int) digestLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_SignInit(long, CKM, long)
     */
    public static long SignInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_SignInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
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
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public static long Sign(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Sign session=0x%08x signatureLen=%d\n  data (len=%d):\n", session, signatureLen.value(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_Sign(session, data, baLen(data), signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_Sign rv=0x%08x{%s}\n  signature (len=%d):\n", rv, CKR.L2S(rv), signatureLen.value()));
            Hex.dump(sb, signature, 0, (int) signatureLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     */
    public static long SignUpdate(long session, byte[] part) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignUpdate session=0x%08x\n  part (len=%d):\n", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_SignUpdate(session, part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignUpdate rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param session the session's handle
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public static long SignFinal(long session, byte[] signature, LongRef signatureLen) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignFinal session=0x%08x signatureLen=%d", session, signatureLen.value()));
        long rv =NATIVE.C_SignFinal(session, signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignFinal rv=0x%08x{%s}\n  signature (len=%d):\n", rv, CKR.L2S(rv), signatureLen.value()));
            Hex.dump(sb, signature, 0, (int) signatureLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    public static long SignRecoverInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_SignRecoverInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_SignRecoverInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_SignRecoverInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param session the session's handle
     * @param data the data to sign
     * @param signature gets the signature
     * @param signatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public static long SignRecover(long session, byte[] data, byte[] signature, LongRef signatureLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignRecover session=0x%08x signatureLen=%d\n  data (len=%d):\n", session, signatureLen.value(), data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_SignRecover(session, data, baLen(data), signature, signatureLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignRecover rv=0x%08x{%s}\n  signature (len=%d):\n", rv, CKR.L2S(rv), signatureLen.value()));
            Hex.dump(sb, signature, 0, (int) signatureLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     */
    public static long VerifyInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_VerifyInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_VerifyInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param session the session's handle
     * @param data signed data
     * @param signature signature
     * @return {@link CKR} return code
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public static long Verify(long session, byte[] data, byte[] signature) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_Verify session=0x%08x\n  data (len=%d):\n", session, data.length));
            Hex.dump(sb, data, 0, data.length, "  ", 32, false);
            sb.append("\n  signature (len=%d):\n");
            Hex.dump(sb, signature, 0, signature.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_Verify(session, data, baLen(data), signature, baLen(signature));
        log.debug(String.format("< C_Verify rv=0x%08x{%s} ", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature.
     * @param session the session's handle
     * @param part signed data
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    public static long VerifyUpdate(long session, byte[] part) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyUpdate session=0x%08x\n  part (len=%d):\n", session, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_VerifyUpdate(session, part, baLen(part));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyUpdate rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    public static long VerifyFinal(long session, byte[] signature) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyFinal session=0x%08x\n  signature (len=%d):\n", session, signature.length));
            Hex.dump(sb, signature, 0, signature.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_VerifyFinal(session, signature, baLen(signature));
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyFinal rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param mechanism the verification mechanism
     * @param key verification key
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    public static long VerifyRecoverInit(long session, CKM mechanism, long key) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_VerifyRecoverInit session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_VerifyRecoverInit(session, mechanism, key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_VerifyRecoverInit rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param session the session's handle
     * @param signature signature to verify
     * @param data gets signed data
     * @param dataLen gets signed data length
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public static long VerifyRecover(long session, byte[] signature, byte[] data, LongRef dataLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_VerifyRecover session=0x%08x dataLen=%d\n  signature (len=%d):\n", session, dataLen.value(), signature.length));
            Hex.dump(sb, signature, 0, signature.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_VerifyRecover(session, signature, baLen(signature), data, dataLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_VerifyRecover rv=0x%08x{%s}\n  data (len=%d):\n", rv, CKR.L2S(rv), dataLen.value()));
            Hex.dump(sb, data, 0, (int) dataLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], long)
     */
    public static long DigestEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DigestEncryptUpdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):\n", session, encryptedPartLen, part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_DigestEncryptUpdate(session, part, baLen(part),
                encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DigestEncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):\n", rv, CKR.L2S(rv), encryptedPartLen));
            Hex.dump(sb, encryptedPart, 0, (int) encryptedPartLen.value, "  ", 32, false);
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
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    public static long DecryptDigestUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptDigestUpdate session=0x%08x partLen=%d\n  encryptedPart (len=%d):\n", session, partLen.value(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_DecryptDigestUpdate(session,
                encryptedPart, baLen(encryptedPart), part, partLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptDigestUpdate rv=0x%08x{%s}\n  part (len=%d):\n", rv, CKR.L2S(rv), partLen.value()));
            Hex.dump(sb, part, 0, (int) partLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public static long SignEncryptUpdate(long session, byte[] part, byte[] encryptedPart, LongRef encryptedPartLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SignEncryptUdate session=0x%08x encryptedPartLen=%d\n  part (len=%d):\n", session, encryptedPartLen.value(), part.length));
            Hex.dump(sb, part, 0, part.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_SignEncryptUpdate(session, part, baLen(part),
                encryptedPart, encryptedPartLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_SignEncryptUpdate rv=0x%08x{%s}\n  encryptedPart (len=%d):\n", rv, CKR.L2S(rv), encryptedPartLen.value()));
            Hex.dump(sb, encryptedPart, 0, (int) encryptedPartLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public static long DecryptVerifyUpdate(long session, byte[] encryptedPart, byte[] part, LongRef partLen) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DecryptVerifyUpdate session=0x%08x partLen=%d\n  encryptedPart (len=%d):\n", session, partLen.value(), encryptedPart.length));
            Hex.dump(sb, encryptedPart, 0, encryptedPart.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_DecryptVerifyUpdate(session,
                encryptedPart, baLen(encryptedPart), part, partLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_DecryptVerifyUpdate rv=0x%08x{%s}\n  part (len=%d):\n", rv, CKR.L2S(rv), partLen.value()));
            Hex.dump(sb, part, 0, (int) partLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_GenerateKey(long, CKM, Template, long, LongRef)
     */
    public static long GenerateKey(long session, CKM mechanism, CKA[] templ, LongRef key) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GenerateKey session=0x%08x %s\n", session, mechanism));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_GenerateKey(session, mechanism, templ, templLen(templ), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GenerateKey rv=0x%08x{%s} key=0x%08x", rv, CKR.L2S(rv), key.value()));
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
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, Template, long, Template, long, LongRef, LongRef)
     */
    public static long GenerateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate,
            CKA[] privateKeyTemplate, LongRef publicKey, LongRef privateKey) {
        if (publicKey == null) {
            publicKey = new LongRef();
        }
        if (privateKey == null) {
            privateKey = new LongRef();
        }

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_GenerateKeyPair session=0x%08x\n  %s", session, mechanism));
            sb.append("\n  publicKeyTemplate:\n");
            dumpTemplate(sb, publicKeyTemplate);
            sb.append("\n  privateKeyTemplate:\n");
            dumpTemplate(sb, privateKeyTemplate);
            log.debug(sb);
        }
        long rv =NATIVE.C_GenerateKeyPair(session, mechanism,
                publicKeyTemplate, templLen(publicKeyTemplate), privateKeyTemplate, templLen(privateKeyTemplate), publicKey, privateKey);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GenerateKeyPair rv=0x%08x{%s} publicKey=0x%08x privateKey=0x%08x", rv, CKR.L2S(rv), publicKey.value(), privateKey.value()));
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
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public static long WrapKey(long session, CKM mechanism, long wrappingKey, long key,
            byte[] wrappedKey, LongRef wrappedKeyLen) {

        if (log.isDebugEnabled()) log.debug(String.format("> C_WrapKey session=0x%08x key=0x%08x\n  %s", session, key, mechanism));
        long rv =NATIVE.C_WrapKey(session, mechanism, wrappingKey,
                key, wrappedKey, wrappedKeyLen);
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_WrapKey rv=0x%08x{%s}\n  wrappedKey (len=%d):\n", rv, CKR.L2S(rv), wrappedKeyLen.value()));
            Hex.dump(sb, wrappedKey, 0, (int) wrappedKeyLen.value(), "  ", 32, false);
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
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, Template, long, LongRef)
     */
    public static long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey,
            CKA[] templ, LongRef key) {

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_UnwrapKey session=0x%08x unwrappingKey=0x%08x %s\n  wrappedKey (len=%d):\n", session, unwrappingKey, mechanism, wrappedKey.length));
            Hex.dump(sb, wrappedKey, 0, wrappedKey.length, "  ", 32, false);
            sb.append('\n');
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_UnwrapKey(session, mechanism, unwrappingKey,
                wrappedKey, baLen(wrappedKey), templ, templLen(templ), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_UnwrapKey rv=0x%08x{%s} key=0x%08x", rv, CKR.L2S(rv), key.value()));
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
     * @see NativeProvider#C_DeriveKey(long, CKM, long, Template, long, LongRef)
     */
    public static long DeriveKey(long session, CKM mechanism, long baseKey, CKA[] templ, LongRef key) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_DeriveKey session=0x%08x baseKey=0x%08x %s\n", session, baseKey, mechanism));
            dumpTemplate(sb, templ);
            log.debug(sb);
        }
        long rv =NATIVE.C_DeriveKey(session, mechanism, baseKey, templ, templLen(templ), key);
        if (log.isDebugEnabled()) log.debug(String.format("< C_DeriveKey rv=0x%08x{%s} key=0x%08x", rv, CKR.L2S(rv), key.value()));
        return rv;
    }

    /**
     * Mixes additional seed material into the token's random number generator.
     * @param session the session's handle
     * @param seed the seed material
     * @return {@link CKR} return code
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    public static long SeedRandom(long session, byte[] seed) {
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("> C_SeedRandom session=0x%08x\n  seed (len=%d):\n", session, seed.length));
            Hex.dump(sb, seed, 0, seed.length, "  ", 32, false);
            log.debug(sb);
        }
        long rv =NATIVE.C_SeedRandom(session, seed, baLen(seed));
        if (log.isDebugEnabled()) log.debug(String.format("< C_SeedRandom rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Generates random or pseudo-random data.
     * @param session the session's handle
     * @param randomData receives the random data
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public static long GenerateRandom(long session, byte[] randomData) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GenerateRandom session=0x%08x randomLen=%d", session, randomData.length));
        long rv =NATIVE.C_GenerateRandom(session, randomData, baLen(randomData));
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder(String.format("< C_GenerateRandom rv=0x%08x{%s}\n  randomData (len=%d):\n", rv, CKR.L2S(rv), randomData.length));
            Hex.dump(sb, randomData, 0, randomData.length, "  ", 32, false);
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
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public static long GetFunctionStatus(long session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_GetFunctionStatus session=0x%08x", session));
        long rv =NATIVE.C_GetFunctionStatus(session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_GetFunctionStatus rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param session the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CancelFunction(long)
     */
    public static long CancelFunction(long session) {
        if (log.isDebugEnabled()) log.debug(String.format("> C_CancelFunction session=0x%08x", session));
        long rv =NATIVE.C_CancelFunction(session);
        if (log.isDebugEnabled()) log.debug(String.format("< C_CancelFunction rv=0x%08x{%s}", rv, CKR.L2S(rv)));
        return rv;
    }

    /**
     * Return length of buf (0 if buf is null).
     * @param buf buf
     * @return length of buf (0 if buf is null)
     */
    private static int baLen(byte[] buf) {
        return buf == null ? 0 : buf.length;
    }

    /**
     * Return length of template (0 if template is null).
     * @param templ template
     * @return length of template (0 if template is null)
     */
    private static int templLen(CKA[] templ) {
        return templ == null ? 0 : templ.length;
    }

    /**
     * Dump for debug.
     * @param sb write to
     */
    private static void dumpTemplate(StringBuilder sb, CKA[] template) {
        int templateLen = templLen(template);
        sb.append("  template (size=").append(templateLen).append(')');
        for (int i = 0; i < templateLen; i++) {
            sb.append("\n  ");
            template[i].dump(sb);
        }
    }

    /**
     * Helper method.  Adds all public static final long fields in c to map, mapping field value to name.
     * @param c class
     * @return map of field value:name
     */
    public static Map<Long, String> createL2SMap(Class<?> c) {
        Map<Long, String> map = new HashMap<Long, String>();
        try {
            for (Field f : c.getDeclaredFields()) {
                // only put 'public static final long' in map
                if (f.getType() == long.class && Modifier.isPublic(f.getModifiers())
                        && Modifier.isStatic(f.getModifiers()) && Modifier.isFinal(f.getModifiers())) {
                    map.put(f.getLong(null), f.getName());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return map;
    }

    /**
     * Helper method, Maps l to constant name, or value 'unknown %s constant 0x08x' % (ckx, l)'.
     * @param map L2S map
     * @param ckx prefix of constant type, e.g. 'CKA'
     * @param l constant value
     * @return constant name, or value 'unknown %s constant 0x08x' % (ckx, l)'.
     */
    public static String l2s(Map<Long, String> map, String ckx, long l) {
        String s = map.get(l);
        if (s != null) {
            return s;
        } else {
          return String.format("unknown %s constant 0x%08x", ckx, l);
        }
    }

    /**
     * Helper method.  String format of flags.
     * @param l2s l2s map
     * @param flags flags
     * @return string format of flags
     */
    public static String f2s(Map<Long, String> l2s, long flags) {
        StringBuilder sb = new StringBuilder();
        String sep = "";
        for (int i = 63; i >= 0; i--) {
            long mask = 1L << i;
            if ((flags & mask) != 0) {
                sb.append(sep);
                sb.append(C.l2s(l2s, "CKF", mask));
                sep = "|";
            }
        }
        return sb.toString();
    }
}
