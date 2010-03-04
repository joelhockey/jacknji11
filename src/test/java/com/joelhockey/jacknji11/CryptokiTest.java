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

import com.joelhockey.jacknji11.CE;
import com.joelhockey.jacknji11.CKM;
import com.joelhockey.jacknji11.CK_INFO;
import com.joelhockey.jacknji11.CK_MECHANISM_INFO;
import com.joelhockey.jacknji11.CK_SLOT_INFO;
import com.joelhockey.jacknji11.CK_TOKEN_INFO;

import junit.framework.TestCase;

public class CryptokiTest extends TestCase {
    private static final byte[] SO_PIN = "sopin".getBytes();
    private static final byte[] USER_PIN = "userpin".getBytes();
    private static final int TESTSLOT = 0;
    private static final int INITSLOT = 1;
    
    public void setUp() {
        CE.Initialize();
    }
    
    public void tearDown() {
        CE.Finalize();
    }
    
    public void testGetInfo() {
        CK_INFO info = new CK_INFO();
        CE.GetInfo(info);
//        System.out.println(info);
    }

    public void testGetSlotList() {
        int[] slots = CE.GetSlotList(true);
//        System.out.println("num slots: " + slots.length);
    }
    
    public void testGetSlotInfo() {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        CE.GetSlotInfo(TESTSLOT, info);
//        System.out.println(info);
    }

    public void testGetTokenInfo() {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        CE.GetTokenInfo(TESTSLOT, info);
//        System.out.println(info);
    }

    public void testGetMechanismList() {
        for (int mech : CE.GetMechanismList(TESTSLOT)) {
//            System.out.println(String.format("0x%08x : %s", mech, CKM.I2S.get(mech)));
        }
    }
    
    public void testGetMechanismInfo() {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        CE.GetMechanismInfo(TESTSLOT, CKM.AES_CBC, info);
//        System.out.println(info);
    }
    
    public void testInitTokenInitPinSetPin() {
        CE.InitToken(INITSLOT, SO_PIN, "TEST".getBytes());
        int session = CE.OpenSession(1, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.SO, SO_PIN);
        CE.InitPIN(session, USER_PIN);
        CE.Logout(session);
        CE.Login(session, CKU.USER, USER_PIN);
        byte[] somenewpin = "somenewpin".getBytes();
        CE.SetPIN(session, USER_PIN, somenewpin);
        CE.SetPIN(session, somenewpin, USER_PIN);
    }
    
    public void testGetSessionInfo() {
        int session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CE.GetSessionInfo(session, sessionInfo);
        System.out.println(sessionInfo);
    }

    public void testGetSessionInfoCloseAllSessions() {
        int s1 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        int s2 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        CE.GetSessionInfo(s2, info );
//        System.out.println(info);
        int s3 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.CloseSession(s1);
        CE.CloseAllSessions(TESTSLOT);
        assertEquals(CKR.SESSION_HANDLE_INVALID, C.CloseSession(s3));
    }
    
    public void testCreateCopyGetSizeDestroyObject() {
        int session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CK_ATTRIBUTE[] templ = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.VALUE, "datavalue"),
        };
        int o1 = CE.CreateObject(session, templ);
        int o2 = CE.CopyObject(session, o1, null);
        CE.DestroyObject(session, o1);
        CE.DestroyObject(session, o2);
    }

    public void testGetObjectSizeGetSetAtt() {
        int session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CK_ATTRIBUTE[] templ = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.VALUE, "datavalue"),
        };
        int o = CE.CreateObject(session, templ);
//        System.out.println("object size: " + CE.GetObjectSize(session, o));
//        System.out.println("label: " + CE.GetAttributeValueStr(session, o, CKA.LABEL));
//        System.out.println("id: " + CE.GetAttributeValueStr(session, o, CKA.ID));
//        System.out.println("data: " + CE.GetAttributeValueStr(session, o, CKA.VALUE));
//        System.out.println("class: " + CKO.I2S.get(CE.GetAttributeValueInt(session, o, CKA.CLASS)));
//        System.out.println("private: " + CE.GetAttributeValueBool(session, o, CKA.PRIVATE));
        templ = new CK_ATTRIBUTE[] {
                new CK_ATTRIBUTE(CKA.LABEL, "datalabel"),
                new CK_ATTRIBUTE(CKA.VALUE, "newdatavalue"),
                new CK_ATTRIBUTE(CKA.ID, "dataid"),
        };
        CE.SetAttributeValue(session, o, templ);
//        System.out.println("object size: " + CE.GetObjectSize(session, o));
//        System.out.println("label: " + CE.GetAttributeValueStr(session, o, CKA.LABEL));
//        System.out.println("id: " + CE.GetAttributeValueStr(session, o, CKA.ID));
//        System.out.println("data: " + CE.GetAttributeValueStr(session, o, CKA.VALUE));
//        System.out.println("class: " + CKO.I2S.get(CE.GetAttributeValueInt(session, o, CKA.CLASS)));
//        System.out.println("private: " + CE.GetAttributeValueBool(session, o, CKA.PRIVATE));
        
        templ = CE.GetAttributeValue(session, o, new int[] {CKA.LABEL, CKA.ID, CKA.VALUE, CKA.CLASS, CKA.PRIVATE});
//        System.out.println("label: " + templ[0].getValueStr());
//        System.out.println("id: " + templ[1].getValueStr());
//        System.out.println("data: " + templ[2].getValueStr());
//        System.out.println("class: " + CKO.I2S.get(templ[3].getValueInt()));
//        System.out.println("private: " + templ[4].getValueBool());
    }
    
/*


    public static native int C_Login(NativeLong session, NativeLong user_type, byte[] pin, NativeLong pin_len);
    public static native int C_Logout(NativeLong session);
    public static native int C_GetAttributeValue(NativeLong session, NativeLong object, Template templ, NativeLong count);
    public static native int C_SetAttributeValue(NativeLong session, NativeLong object, Template templ, NativeLong count);
    public static native int C_FindObjectsInit(NativeLong session, Template templ, NativeLong count);
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
    public static native int C_GenerateKey(NativeLong session, CK_MECHANISM mechanism, Template templ, NativeLong count, LongRef key);
    public static native int C_GenerateKeyPair(NativeLong session, CK_MECHANISM mechanism, Template public_key_template, NativeLong public_key_attribute_count, Template private_key_template, NativeLong private_key_attribute_count, LongRef public_key, LongRef private_key);
    public static native int C_WrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong wrapping_key, NativeLong key, byte[] wrapped_key, LongRef wrapped_key_len);
    public static native int C_UnwrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong unwrapping_key, byte[] wrapped_key, NativeLong wrapped_key_len, Template templ, NativeLong attribute_count, LongRef key);
    public static native int C_DeriveKey(NativeLong session, CK_MECHANISM mechanism, NativeLong base_key, Template templ, NativeLong attribute_count, LongRef key); 
    public static native int C_SeedRandom(NativeLong session, byte[] seed, NativeLong seed_len);
    public static native int C_GenerateRandom(NativeLong session, byte[] random_data, NativeLong random_len);
    public static native int C_GetFunctionStatus(NativeLong session);
    public static native int C_CancelFunction(NativeLong session);


    public static native int C_WaitForSlotEvent(NativeLong flags, LongRef slot, Pointer pReserved);
    public static native int C_GetOperationState(NativeLong session, byte[] operation_state, LongRef operation_state_len);
    public static native int C_SetOperationState(NativeLong session, byte[] operation_state, NativeLong operation_state_len, NativeLong encryption_key, NativeLong authentication_key);
 */
}
