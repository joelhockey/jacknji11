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

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class C {
    private static final byte TRUE = 1;
    private static final byte FALSE = 0;
    
    static {
        Native.register("cryptoki");
    }
    
    public static native int C_Initialize(CK_C_INITIALIZE_ARGS init_args);
    public static native int C_Finalize(Pointer pReserved);
    public static native int C_GetInfo(CK_INFO info);
    public static native int C_GetSlotList(byte token_present, LongArray slot_list, LongRef count);
    public static native int C_GetSlotInfo(NativeLong slotID, CK_SLOT_INFO info);
    public static native int C_GetTokenInfo(NativeLong slotID, CK_TOKEN_INFO info);
    public static native int C_WaitForSlotEvent(NativeLong flags, LongRef slot, Pointer pReserved);
    public static native int C_GetMechanismList(NativeLong slotID, LongArray mechanism_list, LongRef count);
    public static native int C_GetMechanismInfo(NativeLong slotID, NativeLong type, CK_MECHANISM_INFO info);
    public static native int C_InitToken(NativeLong slot_id, byte[] pin, NativeLong pin_len, byte[] label32);
    public static native int C_InitPIN(NativeLong session, byte[] pin, NativeLong pin_len);
    public static native int C_SetPIN(NativeLong session, byte[] old_pin, NativeLong old_len, byte[] new_pin, NativeLong new_len);
    public static native int C_OpenSession(NativeLong slotID, NativeLong flags, Pointer application, CK_NOTIFY notify, LongRef session);
    public static native int C_CloseSession(NativeLong session);
    public static native int C_CloseAllSessions(NativeLong slotID);
    public static native int C_GetSessionInfo(NativeLong session, CK_SESSION_INFO info);
    public static native int C_GetOperationState(NativeLong session, byte[] operation_state, LongRef operation_state_len);
    public static native int C_SetOperationState(NativeLong session, byte[] operation_state, NativeLong operation_state_len, NativeLong encryption_key, NativeLong authentication_key);
    public static native int C_Login(NativeLong session, NativeLong user_type, byte[] pin, NativeLong pin_len);
    public static native int C_Logout(NativeLong session);
    public static native int C_CreateObject(NativeLong session, CK_ATTRIBUTE templ, NativeLong count, LongRef object);
    public static native int C_CopyObject(NativeLong session, NativeLong object, CK_ATTRIBUTE templ, NativeLong count, LongRef new_object);
    public static native int C_DestroyObject(NativeLong session, NativeLong object);
    public static native int C_GetObjectSize(NativeLong session, NativeLong object, LongRef size);
    public static native int C_GetAttributeValue(NativeLong session, NativeLong object, CK_ATTRIBUTE templ, NativeLong count);
    public static native int C_SetAttributeValue(NativeLong session, NativeLong object, CK_ATTRIBUTE templ, NativeLong count);
    public static native int C_FindObjectsInit(NativeLong session, CK_ATTRIBUTE templ, NativeLong count);
    public static native int C_FindObjects(NativeLong session, LongArray object, NativeLong max_object_count, LongRef object_count);
    public static native int C_FindObjectsFinal(NativeLong session);
    public static native int C_EncryptInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_Encrypt(NativeLong session, byte[] data, NativeLong data_len, byte[] encrypted_data, LongRef encrypted_data_len);
    public static native int C_EncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_EncryptFinal(NativeLong session, byte[] last_encrypted_part, LongRef last_encrypted_part_len);
    public static native int C_DecryptInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_Decrypt(NativeLong session, byte[] encrypted_data, NativeLong encrypted_data_len, byte[] data, LongRef data_lens);
    public static native int C_DecryptUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] data, LongRef data_len);
    public static native int C_DecryptFinal(NativeLong session, byte[] last_part, LongRef last_part_len);
    public static native int C_DigestInit(NativeLong session, CK_MECHANISM mechanism);
    public static native int C_Digest(NativeLong session, byte[] data, NativeLong data_len, byte[] digest, LongRef digest_len);
    public static native int C_DigestUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_DigestKey(NativeLong session, NativeLong key);
    public static native int C_DigestFinal(NativeLong session, byte[] digest, LongRef digest_len);
    public static native int C_SignInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_Sign(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
    public static native int C_SignUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_SignFinal(NativeLong session, byte[] signature, LongRef signature_len);
    public static native int C_SignRecoverInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_SignRecover(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
    public static native int C_VerifyInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_Verify(NativeLong session, byte[] data, NativeLong data_en, byte[] signature, NativeLong signature_len);
    public static native int C_VerifyUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_VerifyFinal(NativeLong session, byte[] signature, NativeLong signature_len);
    public static native int C_VerifyRecoverInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
    public static native int C_VerifyRecover(NativeLong session, byte[] signature, NativeLong signature_len, byte[] data, LongRef data_len);
    public static native int C_DigestEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_DecryptDigestUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
    public static native int C_SignEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_DecryptVerifyUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
    public static native int C_GenerateKey(NativeLong session, CK_MECHANISM mechanism, CK_ATTRIBUTE templ, NativeLong count, LongRef key);
    public static native int C_GenerateKeyPair(NativeLong session, CK_MECHANISM mechanism, CK_ATTRIBUTE public_key_template, NativeLong public_key_attribute_count, CK_ATTRIBUTE private_key_template, NativeLong private_key_attribute_count, LongRef public_key, LongRef private_key);
    public static native int C_WrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong wrapping_key, NativeLong key, byte[] wrapped_key, LongRef wrapped_key_len);
    public static native int C_UnwrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong unwrapping_key, byte[] wrapped_key, NativeLong wrapped_key_len, CK_ATTRIBUTE templ, NativeLong attribute_count, LongRef key);
    public static native int C_DeriveKey(NativeLong session, CK_MECHANISM mechanism, NativeLong base_key, CK_ATTRIBUTE templ, NativeLong attribute_count, LongRef key); 
    public static native int C_SeedRandom(NativeLong session, byte[] seed, NativeLong seed_len);
    public static native int C_GenerateRandom(NativeLong session, byte[] random_data, NativeLong random_len);
    public static native int C_GetFunctionStatus(NativeLong session);
    public static native int C_CancelFunction(NativeLong session);
    
    public static int Initialize() {
        return C_Initialize(null);
    }
    public static int Finalize() {
        return C_Finalize(null);
    }
    public static int GetInfo(CK_INFO info) {
        int rv = C_GetInfo(info);
        info.read();
        return rv;
    }
    public static int GetSlotList(boolean tokenPresent, int[] slotList, LongRef count) {
        LongArray slotsRef = new LongArray(slotList); 
        int rv = C_GetSlotList(tokenPresent ? TRUE : FALSE, slotsRef, count);
        slotsRef.update(slotList);
        return rv;
    }
    public static int GetSlotInfo(int slotID, CK_SLOT_INFO info) {
        int rv = C_GetSlotInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }
    public static int GetTokenInfo(int slotID, CK_TOKEN_INFO info) {
        int rv = C_GetTokenInfo(new NativeLong(slotID), info);
        info.read();
        return rv;
    }
    public static int WaitForSlotEvent(int flags, LongRef slot, Pointer pReserved) {
        return C_WaitForSlotEvent(new NativeLong(flags), slot, pReserved);
    }
    public static int GetMechanismList(int slotID, int[] mechanismList, LongRef count) {
        LongArray longArray = new LongArray(mechanismList);
        int rv = C_GetMechanismList(new NativeLong(slotID), longArray, count);
        longArray.update(mechanismList);
        return rv;
    }
    public static int GetMechanismInfo(int slotID, int type, CK_MECHANISM_INFO info) {
        return C_GetMechanismInfo(new NativeLong(slotID), new NativeLong(type), info);
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
        return C_InitToken(new NativeLong(slotID), pin, baLen(pin), label32);
    }
    public static int InitPIN(int session, byte[] pin) {
        return C_InitPIN(new NativeLong(session), pin, baLen(pin));
    }
    public static int SetPIN(int session, byte[] old_pin, byte[] new_pin) {
        return C_SetPIN(new NativeLong(session), old_pin, baLen(old_pin), new_pin, baLen(new_pin));
    }
    public static int OpenSession(int slotID, int flags, Pointer application, CK_NOTIFY notify, LongRef session) {
        return C_OpenSession(new NativeLong(slotID), new NativeLong(flags), application, notify, session);
    }
    public static int CloseSession(int session) {
        return C_CloseSession(new NativeLong(session));
    }
    public static int CloseAllSessions(int slotID) {
        return C_CloseAllSessions(new NativeLong(slotID));
    }
    public static int GetSessionInfo(int session, CK_SESSION_INFO info) {
        return C_GetSessionInfo(new NativeLong(session), info);
    }
    public static int GetOperationState(int session, byte[] operation_state, LongRef operation_state_len) {
        return C_GetOperationState(new NativeLong(session), operation_state, operation_state_len);
    }
    public static int SetOperationState(int session, byte[] operation_state, int encryption_key, int authentication_key) {
        return C_SetOperationState(new NativeLong(session), operation_state, baLen(operation_state), new NativeLong(encryption_key), new NativeLong(authentication_key));
    }
    public static int Login(int session, int user_type, byte[] pin) {
        return C_Login(new NativeLong(session), new NativeLong(user_type), pin, baLen(pin));
    }
    public static int Logout(int session) {
        return C_Logout(new NativeLong(session));
    }
    public static int CreateObject(int session, CK_ATTRIBUTE[] templ, LongRef object) {
        return C_CreateObject(new NativeLong(session), attPtr(templ), attLen(templ), object);
    }
    public static int CopyObject(int session, int object, CK_ATTRIBUTE[] templ, LongRef new_object) {
        return C_CopyObject(new NativeLong(session), new NativeLong(object), attPtr(templ), attLen(templ), new_object);
    }
    public static int DestroyObject(int session, int object) {
        return C_DestroyObject(new NativeLong(session), new NativeLong(object));
    }
    public static int GetObjectSize(int session, int object, LongRef size) {
        return C_GetObjectSize(new NativeLong(session), new NativeLong(object), size);
    }
    public static int GetAttributeValue(int session, int object, CK_ATTRIBUTE[] templ) {
        return C_GetAttributeValue(new NativeLong(session), new NativeLong(object), attPtr(templ), attLen(templ));
    }
    public static int SetAttributeValue(int session, int object, CK_ATTRIBUTE[] templ) {
        return C_SetAttributeValue(new NativeLong(session), new NativeLong(object), attPtr(templ), attLen(templ));
    }
    public static int FindObjectsInit(int session, CK_ATTRIBUTE[] templ) {
        return C_FindObjectsInit(new NativeLong(session), attPtr(templ), attLen(templ));
    }
    public static int FindObjects(int session, int[] found, LongRef object_count) {
        LongArray longArray = new LongArray(found);
        int rv = C_FindObjects(new NativeLong(session), longArray, new NativeLong(found == null ? 0 : found.length), object_count);
        longArray.update(found);
        return rv;
    }
    public static int FindObjectsFinal(int session) {
        return C_FindObjectsFinal(new NativeLong(session));
    }
    public static int EncryptInit(int session, CK_MECHANISM mechanism, int key) {
        return C_EncryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Encrypt(int session, byte[] data, byte[] encrypted_data, LongRef encrypted_data_len) {
        return C_Encrypt(new NativeLong(session), data, baLen(data), encrypted_data, encrypted_data_len);
    }
    public static int EncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return C_EncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int EncryptFinal(int session, byte[] last_encrypted_part, LongRef last_encrypted_part_len) {
        return C_EncryptFinal(new NativeLong(session), last_encrypted_part, last_encrypted_part_len);
    }
    public static int DecryptInit(int session, CK_MECHANISM mechanism, int key) {
        return C_DecryptInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Decrypt(int session, byte[] encrypted_data, byte[] data, LongRef data_lens) {
        return C_Decrypt(new NativeLong(session), encrypted_data, baLen(encrypted_data), data, data_lens);
    }
    public static int DecryptUpdate(int session, byte[] encrypted_part, byte[] data, LongRef data_len) {
        return C_DecryptUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), data, data_len);
    }
    public static int DecryptFinal(int session, byte[] last_part, LongRef last_part_len) {
        return C_DecryptFinal(new NativeLong(session), last_part, last_part_len);
    }
    public static int DigestInit(int session, CK_MECHANISM mechanism) {
        return C_DigestInit(new NativeLong(session), mechanism);
    }
    public static int Digest(int session, byte[] data, byte[] digest, LongRef digest_len) {
        return C_Digest(new NativeLong(session), data, baLen(data), digest, digest_len);
    }
    public static int DigestUpdate(int session, byte[] part) {
        return C_DigestUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int DigestKey(int session, int key) {
        return C_DigestKey(new NativeLong(session), new NativeLong(key));
    }
    public static int DigestFinal(int session, byte[] digest, LongRef digest_len) {
        return C_DigestFinal(new NativeLong(session), digest, digest_len);
    }
    public static int SignInit(int session, CK_MECHANISM mechanism, int key) {
        return C_SignInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Sign(int session, byte[] data, byte[] signature, LongRef signature_len) {
        return C_Sign(new NativeLong(session), data, baLen(data), signature, signature_len);
    }
    public static int SignUpdate(int session, byte[] part) {
        return C_SignUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int SignFinal(int session, byte[] signature, LongRef signature_len) {
        return C_SignFinal(new NativeLong(session), signature, signature_len);
    }
    public static int SignRecoverInit(int session, CK_MECHANISM mechanism, int key) {
        return C_SignRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int SignRecover(int session, byte[] data, byte[] signature, LongRef signature_len) {
        return C_SignRecover(new NativeLong(session), data, baLen(data), signature, signature_len);
    }
    public static int VerifyInit(int session, CK_MECHANISM mechanism, int key) {
        return C_VerifyInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int Verify(int session, byte[] data, byte[] signature) {
        return C_Verify(new NativeLong(session), data, baLen(data), signature, baLen(signature));
    }
    public static int VerifyUpdate(int session, byte[] part) {
        return C_VerifyUpdate(new NativeLong(session), part, baLen(part));
    }
    public static int VerifyFinal(int session, byte[] signature) {
        return C_VerifyFinal(new NativeLong(session), signature, baLen(signature));
    }
    public static int VerifyRecoverInit(int session, CK_MECHANISM mechanism, int key) {
        return C_VerifyRecoverInit(new NativeLong(session), mechanism, new NativeLong(key));
    }
    public static int VerifyRecover(int session, byte[] signature, byte[] data, LongRef data_len) {
        return C_VerifyRecover(new NativeLong(session), signature, baLen(signature), data, data_len);
    }
    public static int DigestEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return C_DigestEncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int DecryptDigestUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        return C_DecryptDigestUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), part, part_len);
    }
    public static int SignEncryptUpdate(int session, byte[] part, byte[] encrypted_part, LongRef encrypted_part_len) {
        return C_SignEncryptUpdate(new NativeLong(session), part, baLen(part), encrypted_part, encrypted_part_len);
    }
    public static int DecryptVerifyUpdate(int session, byte[] encrypted_part, byte[] part, LongRef part_len) {
        return C_DecryptVerifyUpdate(new NativeLong(session), encrypted_part, baLen(encrypted_part), part, part_len);
    }
    public static int GenerateKey(int session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] templ, LongRef key) {
        return C_GenerateKey(new NativeLong(session), mechanism, attPtr(templ), attLen(templ), key);
    }
    public static int GenerateKeyPair(int session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] public_key_template, CK_ATTRIBUTE[] private_key_template, LongRef public_key, LongRef private_key) {
        return C_GenerateKeyPair(new NativeLong(session), mechanism, attPtr(public_key_template), attLen(public_key_template), attPtr(private_key_template), attLen(private_key_template), public_key, private_key);
    }
    public static int WrapKey(int session, CK_MECHANISM mechanism, int wrapping_key, int key, byte[] wrapped_key, LongRef wrapped_key_len) {
        return C_WrapKey(new NativeLong(session), mechanism, new NativeLong(wrapping_key), new NativeLong(key), wrapped_key, wrapped_key_len);
    }
    public static int UnwrapKey(int session, CK_MECHANISM mechanism, int unwrapping_key, byte[] wrapped_key, CK_ATTRIBUTE[] templ, LongRef key) {
        return C_UnwrapKey(new NativeLong(session), mechanism, new NativeLong(unwrapping_key), wrapped_key, baLen(wrapped_key), attPtr(templ), attLen(templ), key);
    }
    public static int DeriveKey(int session, CK_MECHANISM mechanism, int base_key, CK_ATTRIBUTE[] templ, LongRef key) {
        return C_DeriveKey(new NativeLong(session), mechanism, new NativeLong(base_key), attPtr(templ), attLen(templ), key);
    } 
    public static int SeedRandom(int session, byte[] seed) {
        return C_SeedRandom(new NativeLong(session), seed, baLen(seed));
    }
    public static int GenerateRandom(int session, byte[] random_data) {
        return C_GenerateRandom(new NativeLong(session), random_data, baLen(random_data));
    }
    public static int GetFunctionStatus(int session) {
        return C_GetFunctionStatus(new NativeLong(session));
    }
    public static int CancelFunction(int session) {
        return C_CancelFunction(new NativeLong(session));
    }
    
    private static NativeLong baLen(byte[] buf) { return new NativeLong(buf == null ? 0 : buf.length); }
    private static NativeLong attLen(CK_ATTRIBUTE[] templ) { return new NativeLong(templ == null ? 0 : templ.length); }
    private static CK_ATTRIBUTE attPtr(CK_ATTRIBUTE[] templ) { return templ == null || templ.length == 0 ? null : templ[0]; }
}
