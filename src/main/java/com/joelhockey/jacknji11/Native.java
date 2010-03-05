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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class Native {
    private static final byte TRUE = 1;
    private static final byte FALSE = 0;
    
    static {
        com.sun.jna.Native.register("cryptoki");
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
    public static native int C_CreateObject(NativeLong session, Template templ, NativeLong count, LongRef object);
    public static native int C_CopyObject(NativeLong session, NativeLong object, Template templ, NativeLong count, LongRef new_object);
    public static native int C_DestroyObject(NativeLong session, NativeLong object);
    public static native int C_GetObjectSize(NativeLong session, NativeLong object, LongRef size);
    public static native int C_GetAttributeValue(NativeLong session, NativeLong object, Template templ, NativeLong count);
    public static native int C_SetAttributeValue(NativeLong session, NativeLong object, Template templ, NativeLong count);
    public static native int C_FindObjectsInit(NativeLong session, Template templ, NativeLong count);
    public static native int C_FindObjects(NativeLong session, LongArray object, NativeLong max_object_count, LongRef object_count);
    public static native int C_FindObjectsFinal(NativeLong session);
    public static native int C_EncryptInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_Encrypt(NativeLong session, byte[] data, NativeLong data_len, byte[] encrypted_data, LongRef encrypted_data_len);
    public static native int C_EncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_EncryptFinal(NativeLong session, byte[] last_encrypted_part, LongRef last_encrypted_part_len);
    public static native int C_DecryptInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_Decrypt(NativeLong session, byte[] encrypted_data, NativeLong encrypted_data_len, byte[] data, LongRef data_lens);
    public static native int C_DecryptUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] data, LongRef data_len);
    public static native int C_DecryptFinal(NativeLong session, byte[] last_part, LongRef last_part_len);
    public static native int C_DigestInit(NativeLong session, CKM mechanism);
    public static native int C_Digest(NativeLong session, byte[] data, NativeLong data_len, byte[] digest, LongRef digest_len);
    public static native int C_DigestUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_DigestKey(NativeLong session, NativeLong key);
    public static native int C_DigestFinal(NativeLong session, byte[] digest, LongRef digest_len);
    public static native int C_SignInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_Sign(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
    public static native int C_SignUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_SignFinal(NativeLong session, byte[] signature, LongRef signature_len);
    public static native int C_SignRecoverInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_SignRecover(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
    public static native int C_VerifyInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_Verify(NativeLong session, byte[] data, NativeLong data_en, byte[] signature, NativeLong signature_len);
    public static native int C_VerifyUpdate(NativeLong session, byte[] part, NativeLong part_len);
    public static native int C_VerifyFinal(NativeLong session, byte[] signature, NativeLong signature_len);
    public static native int C_VerifyRecoverInit(NativeLong session, CKM mechanism, NativeLong key);
    public static native int C_VerifyRecover(NativeLong session, byte[] signature, NativeLong signature_len, byte[] data, LongRef data_len);
    public static native int C_DigestEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_DecryptDigestUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
    public static native int C_SignEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
    public static native int C_DecryptVerifyUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
    public static native int C_GenerateKey(NativeLong session, CKM mechanism, Template templ, NativeLong count, LongRef key);
    public static native int C_GenerateKeyPair(NativeLong session, CKM mechanism, Template public_key_template, NativeLong public_key_attribute_count, Template private_key_template, NativeLong private_key_attribute_count, LongRef public_key, LongRef private_key);
    public static native int C_WrapKey(NativeLong session, CKM mechanism, NativeLong wrapping_key, NativeLong key, byte[] wrapped_key, LongRef wrapped_key_len);
    public static native int C_UnwrapKey(NativeLong session, CKM mechanism, NativeLong unwrapping_key, byte[] wrapped_key, NativeLong wrapped_key_len, Template templ, NativeLong attribute_count, LongRef key);
    public static native int C_DeriveKey(NativeLong session, CKM mechanism, NativeLong base_key, Template templ, NativeLong attribute_count, LongRef key); 
    public static native int C_SeedRandom(NativeLong session, byte[] seed, NativeLong seed_len);
    public static native int C_GenerateRandom(NativeLong session, byte[] random_data, NativeLong random_len);
    public static native int C_GetFunctionStatus(NativeLong session);
    public static native int C_CancelFunction(NativeLong session);
}
