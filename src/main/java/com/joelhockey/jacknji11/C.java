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

import java.util.Arrays;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class C {
    private static final byte TRUE = 1;
    private static final byte FALSE = 0;
    
    public static int Initialize() {
        return Native.C_Initialize(null);
    }
    public static int Finalize() {
        return Native.C_Finalize(null);
    }
    public static int GetInfo(CK_INFO info) {
        int rv = Native.C_GetInfo(info);
        info.read();
        return rv;
    }
    public static int GetSlotList(boolean tokenPresent, int[] slotList, LongRef count) {
        LongArray slotsRef = new LongArray(slotList); 
        int rv = Native.C_GetSlotList(tokenPresent ? TRUE : FALSE, slotsRef, count);
        slotsRef.update(slotList);
        return rv;
    }
    public static int GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = Native.C_GetSlotInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }
    public static int GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = Native.C_GetTokenInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }
    public static int WaitForSlotEvent(int flags, LongRef slot, Pointer pReserved) {
        return Native.C_WaitForSlotEvent(new NativeLong(flags), slot, pReserved);
    }
    public static int GetMechanismList(int slotID, int[] mechanismList, LongRef count) {
        LongArray longArray = new LongArray(mechanismList);
        int rv = Native.C_GetMechanismList(new NativeLong(slotID), longArray, count);
        longArray.update(mechanismList);
        return rv;
    }
    public static int GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        return Native.C_GetMechanismInfo(new NativeLong(slotID), new NativeLong(type), info);
    }
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
        return Native.C_InitToken(new NativeLong(slotID), pin, baLen(pin), label32);
    }
    public static int InitPIN(int session, byte[] pin) {
        return Native.C_InitPIN(new NativeLong(session), pin, baLen(pin));
    }
    public static int SetPIN(int session, byte[] old_pin, byte[] new_pin) {
        return Native.C_SetPIN(new NativeLong(session), old_pin, baLen(old_pin), new_pin, baLen(new_pin));
    }
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        return Native.C_OpenSession(new NativeLong(slotID), new NativeLong(flags), application, notify, session);
    }
    public static int CloseSession(int session) {
        return Native.C_CloseSession(new NativeLong(session));
    }
    public static int CloseAllSessions(int slotID) {
        return Native.C_CloseAllSessions(new NativeLong(slotID));
    }
    public static int GetSessionInfo(int session, CK_SESSION_INFO info) {
        return Native.C_GetSessionInfo(new NativeLong(session), info);
    }
    public static int GetOperationState(int session, byte[] operation_state, LongRef operation_state_len) {
        return Native.C_GetOperationState(new NativeLong(session), operation_state, operation_state_len);
    }
    public static int SetOperationState(int session, byte[] operation_state, int encryption_key, int authentication_key) {
        return Native.C_SetOperationState(new NativeLong(session), operation_state, baLen(operation_state), new NativeLong(encryption_key), new NativeLong(authentication_key));
    }
    public static int Login(int session, int user_type, byte[] pin) {
        return Native.C_Login(new NativeLong(session), new NativeLong(user_type), pin, baLen(pin));
    }
    public static int Logout(int session) {
        return Native.C_Logout(new NativeLong(session));
    }
    public static int CreateObject(int session, CK_ATTRIBUTE[] templ, LongRef object) {
        return Native.C_CreateObject(new NativeLong(session), new Template(templ), attLen(templ), object);
    }
    public static int CopyObject(int session, int object, CK_ATTRIBUTE[] templ, LongRef new_object) {
        return Native.C_CopyObject(new NativeLong(session), new NativeLong(object), new Template(templ), attLen(templ), new_object);
    }
    public static int DestroyObject(int session, int object) {
        return Native.C_DestroyObject(new NativeLong(session), new NativeLong(object));
    }
    public static int GetObjectSize(int session, int object, LongRef size) {
        return Native.C_GetObjectSize(new NativeLong(session), new NativeLong(object), size);
    }
    public static int GetAttributeValue(int session, int object, CK_ATTRIBUTE[] templ) {
        Template template = new Template(templ);
        int rv = Native.C_GetAttributeValue(new NativeLong(session), new NativeLong(object), template, attLen(templ));
        template.update(templ);
        return rv;
    }
    public static int SetAttributeValue(int session, int object, CK_ATTRIBUTE[] templ) {
        return Native.C_SetAttributeValue(new NativeLong(session), new NativeLong(object), new Template(templ), attLen(templ));
    }
    public static int FindObjectsInit(int session, CK_ATTRIBUTE[] templ) {
        return Native.C_FindObjectsInit(new NativeLong(session), new Template(templ), attLen(templ));
    }
    public static int FindObjects(int session, int[] found, LongRef object_count) {
        LongArray longArray = new LongArray(found);
        int rv = Native.C_FindObjects(new NativeLong(session), longArray, new NativeLong(found == null ? 0 : found.length), object_count);
        longArray.update(found);
        return rv;
    }
    public static int FindObjectsFinal(int session) {
        return Native.C_FindObjectsFinal(new NativeLong(session));
    }
    public static int EncryptInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_EncryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Encrypt(int session, byte[] data, byte[] encrypted_data, LongRef encrypted_data_len) {
        return Native.C_Encrypt(new NativeLong(session), data, baLen(data), encrypted_data, encrypted_data_len);
    }
    public static int EncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return Native.C_EncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int EncryptFinal(int session, byte[] last_encrypted_part, LongRef last_encrypted_part_len) {
        return Native.C_EncryptFinal(new NativeLong(session), last_encrypted_part, last_encrypted_part_len);
    }
    public static int DecryptInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_DecryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Decrypt(int session, byte[] encrypted_data, byte[] data, LongRef data_lens) {
        return Native.C_Decrypt(new NativeLong(session), encrypted_data, baLen(encrypted_data), data, data_lens);
    }
    public static int DecryptUpdate(int session, byte[] encrypted_part, byte[] data, LongRef data_len) {
        return Native.C_DecryptUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), data, data_len);
    }
    public static int DecryptFinal(int session, byte[] last_part, LongRef last_part_len) {
        return Native.C_DecryptFinal(new NativeLong(session), last_part, last_part_len);
    }
    public static int DigestInit(int session, CK_MECHANISM mechanism) {
        return Native.C_DigestInit(new NativeLong(session), mechanism);
    }
    public static int Digest(int session, byte[] data, byte[] digest, LongRef digest_len) {
        return Native.C_Digest(new NativeLong(session), data, baLen(data), digest, digest_len);
    }
    public static int DigestUpdate(int session, byte[] part) {
        return Native.C_DigestUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int DigestKey(int session, int key) {
        return Native.C_DigestKey(new NativeLong(session), new NativeLong(key));
    }
    public static int DigestFinal(int session, byte[] digest, LongRef digest_len) {
        return Native.C_DigestFinal(new NativeLong(session), digest, digest_len);
    }
    public static int SignInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_SignInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Sign(int session, byte[] data, byte[] signature, LongRef signature_len) {
        return Native.C_Sign(new NativeLong(session), data, baLen(data), signature, signature_len);
    }
    public static int SignUpdate(int session, byte[] part) {
        return Native.C_SignUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int SignFinal(int session, byte[] signature, LongRef signature_len) {
        return Native.C_SignFinal(new NativeLong(session), signature, signature_len);
    }
    public static int SignRecoverInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_SignRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int SignRecover(int session, byte[] data, byte[] signature, LongRef signature_len) {
        return Native.C_SignRecover(new NativeLong(session), data, baLen(data), signature, signature_len);
    }
    public static int VerifyInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_VerifyInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Verify(int session, byte[] data, byte[] signature) {
        return Native.C_Verify(new NativeLong(session), data, baLen(data), signature, baLen(signature));
    }
    public static int VerifyUpdate(int session, byte[] part) {
        return Native.C_VerifyUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int VerifyFinal(int session, byte[] signature) {
        return Native.C_VerifyFinal(new NativeLong(session), signature, baLen(signature));
    }
    public static int VerifyRecoverInit(int session, CK_MECHANISM mechanism, int key) {
        return Native.C_VerifyRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int VerifyRecover(int session, byte[] signature, byte[] data, LongRef data_len) {
        return Native.C_VerifyRecover(new NativeLong(session), signature, baLen(signature), data, data_len);
    }
    public static int DigestEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return Native.C_DigestEncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int DecryptDigestUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        return Native.C_DecryptDigestUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), part, part_len);
    }
    public static int SignEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return Native.C_SignEncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int DecryptVerifyUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        return Native.C_DecryptVerifyUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), part, part_len);
    }
    public static int GenerateKey(int session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] templ, LongRef key) {
        return Native.C_GenerateKey(new NativeLong(session), mechanism, new Template(templ), attLen(templ), key);
    }
    public static int GenerateKeyPair(int session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] public_key_template, CK_ATTRIBUTE[] private_key_template, LongRef public_key, LongRef private_key) {
        return Native.C_GenerateKeyPair(new NativeLong(session), mechanism, new Template(public_key_template), attLen(public_key_template), new Template(private_key_template), attLen(private_key_template), public_key, private_key);
    }
    public static int WrapKey(int session, CK_MECHANISM mechanism, int wrapping_key, int key, byte[] wrapped_key, LongRef wrapped_key_len) {
        return Native.C_WrapKey(new NativeLong(session), mechanism, new NativeLong(wrapping_key), new NativeLong(key), wrapped_key, wrapped_key_len);
    }
    public static int UnwrapKey(int session, CK_MECHANISM mechanism, int unwrapping_key, byte[] wrapped_key, CK_ATTRIBUTE[] templ, LongRef key) {
        return Native.C_UnwrapKey(new NativeLong(session), mechanism, new NativeLong(unwrapping_key), wrapped_key, baLen(wrapped_key), new Template(templ), attLen(templ), key);
    }
    public static int DeriveKey(int session, CK_MECHANISM mechanism, int base_key, CK_ATTRIBUTE[] templ, LongRef key) {
        return Native.C_DeriveKey(new NativeLong(session), mechanism, new NativeLong(base_key), new Template(templ), attLen(templ), key);
    } 
    public static int SeedRandom(int session, byte[] seed) {
        return Native.C_SeedRandom(new NativeLong(session), seed, baLen(seed));
    }
    public static int GenerateRandom(int session, byte[] random_data) {
        return Native.C_GenerateRandom(new NativeLong(session), random_data, baLen(random_data));
    }
    public static int GetFunctionStatus(int session) {
        return Native.C_GetFunctionStatus(new NativeLong(session));
    }
    public static int CancelFunction(int session) {
        return Native.C_CancelFunction(new NativeLong(session));
    }
    
    private static NativeLong baLen(byte[] buf) { return new NativeLong(buf == null ? 0 : buf.length); }
    private static NativeLong attLen(CK_ATTRIBUTE[] templ) { return new NativeLong(templ == null ? 0 : templ.length); }
}
