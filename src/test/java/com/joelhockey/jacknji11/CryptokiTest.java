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
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.VALUE, "datavalue"),
        };
        int o1 = CE.CreateObject(session, templ);
        int o2 = CE.CopyObject(session, o1, null);
        CE.DestroyObject(session, o1);
        CE.DestroyObject(session, o2);
    }

    public void testGetObjectSizeGetSetAtt() {
        int session = CE.OpenSession(TESTSLOT);
        CE.Login(session, CKU.USER, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.VALUE, "datavalue"),
        };
        int o = CE.CreateObject(session, templ);
        int size = CE.GetObjectSize(session, o);
        assertEquals("", CE.GetAttributeValueStr(session, o, CKA.LABEL));
        assertNull(CE.GetAttributeValueStr(session, o, CKA.ID));
        assertEquals("datavalue", CE.GetAttributeValueStr(session, o, CKA.VALUE));
        assertEquals(Integer.valueOf(CKO.DATA), CE.GetAttributeValueInt(session, o, CKA.CLASS));
        assertFalse(CE.GetAttributeValueBool(session, o, CKA.PRIVATE));
        templ = new CKA[] {
                new CKA(CKA.LABEL, "datalabel"),
                new CKA(CKA.VALUE, "newdatavalue"),
                new CKA(CKA.ID, "dataid"),
        };
        CE.SetAttributeValue(session, o, templ);
        int newsize = CE.GetObjectSize(session, o);
        assertTrue(newsize > size);
        assertEquals("datalabel", CE.GetAttributeValueStr(session, o, CKA.LABEL));
        assertEquals("dataid", CE.GetAttributeValueStr(session, o, CKA.ID));
        assertEquals("newdatavalue", CE.GetAttributeValueStr(session, o, CKA.VALUE));
        assertEquals(Integer.valueOf(CKO.DATA), CE.GetAttributeValueInt(session, o, CKA.CLASS));
        assertFalse(CE.GetAttributeValueBool(session, o, CKA.PRIVATE));
        
        templ = CE.GetAttributeValue(session, o, new int[] {CKA.LABEL, CKA.ID, CKA.VALUE, CKA.CLASS, CKA.PRIVATE});
        assertEquals("datalabel", templ[0].getValueStr());
        assertEquals("dataid", templ[1].getValueStr());
        assertEquals("newdatavalue", templ[2].getValueStr());
        assertEquals(CKO.DATA, templ[3].getValueInt());
        assertFalse(templ[4].getValueBool());
    }

    public void testFindObjects() {
        int session = CE.OpenSession(TESTSLOT);
        // create a few objects
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.LABEL, "label1"),
        };
        int o1 = CE.CreateObject(session, templ);
        int o2 = CE.CreateObject(session, templ);
        int o3 = CE.CreateObject(session, templ);
        assertTrue(o1 != o2);
        templ[1] = new CKA(CKA.LABEL, "label2");
        int o4 = CE.CreateObject(session, templ);
    
        templ = new CKA[] {new CKA(CKA.LABEL, "label1")};
        CE.FindObjectsInit(session, templ);
        int[] found = new int[2];
        assertEquals(2, CE.FindObjects(session, found));
        assertEquals(1, CE.FindObjects(session, found));
        assertEquals(0, CE.FindObjects(session, found));
        CE.FindObjectsFinal(session);
        templ = new CKA[] {new CKA(CKA.LABEL, "label2")};
        CE.FindObjectsInit(session, templ);
        assertEquals(1, CE.FindObjects(session, found));
        assertEquals(o4, found[0]);
        assertEquals(0, CE.FindObjects(session, found));
        CE.FindObjectsFinal(session);
    }
    

    public void testEncryptDecrypt() {
        
        
//        public static native int C_EncryptInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//        public static native int C_Encrypt(NativeLong session, byte[] data, NativeLong data_len, byte[] encrypted_data, LongRef encrypted_data_len);
//        public static native int C_EncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//        public static native int C_EncryptFinal(NativeLong session, byte[] last_encrypted_part, LongRef last_encrypted_part_len);
//        public static native int C_DecryptInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//        public static native int C_Decrypt(NativeLong session, byte[] encrypted_data, NativeLong encrypted_data_len, byte[] data, LongRef data_lens);
//        public static native int C_DecryptUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] data, LongRef data_len);
//        public static native int C_DecryptFinal(NativeLong session, byte[] last_part, LongRef last_part_len);
        
    }

    public void testDigest() {
//        public static native int C_DigestInit(NativeLong session, CK_MECHANISM mechanism);
//        public static native int C_Digest(NativeLong session, byte[] data, NativeLong data_len, byte[] digest, LongRef digest_len);
//        public static native int C_DigestUpdate(NativeLong session, byte[] part, NativeLong part_len);
//        public static native int C_DigestKey(NativeLong session, NativeLong key);
//        public static native int C_DigestFinal(NativeLong session, byte[] digest, LongRef digest_len);
        
    }

    public void testSignVerify() {
//        public static native int C_SignInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//        public static native int C_Sign(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
//        public static native int C_SignUpdate(NativeLong session, byte[] part, NativeLong part_len);
//        public static native int C_SignFinal(NativeLong session, byte[] signature, LongRef signature_len);
//        public static native int C_SignRecoverInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//        public static native int C_SignRecover(NativeLong session, byte[] data, NativeLong data_len, byte[] signature, LongRef signature_len);
//        public static native int C_VerifyInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//        public static native int C_Verify(NativeLong session, byte[] data, NativeLong data_en, byte[] signature, NativeLong signature_len);
//        public static native int C_VerifyUpdate(NativeLong session, byte[] part, NativeLong part_len);
//        public static native int C_VerifyFinal(NativeLong session, byte[] signature, NativeLong signature_len);
        
    }

//    public static native int C_VerifyRecoverInit(NativeLong session, CK_MECHANISM mechanism, NativeLong key);
//    public static native int C_VerifyRecover(NativeLong session, byte[] signature, NativeLong signature_len, byte[] data, LongRef data_len);
//    public static native int C_DigestEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native int C_DecryptDigestUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
//    public static native int C_SignEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native int C_DecryptVerifyUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
  
    
    public void testGenerateKeyWrapUnwrap() {
        int session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.VALUE_LEN, 16),
            new CKA(CKA.LABEL, "label"),
        };
        
        int key = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN), templ);
//        public static native int C_GenerateKey(NativeLong session, CK_MECHANISM mechanism, Template templ, NativeLong count, LongRef key);
//        public static native int C_GenerateKeyPair(NativeLong session, CK_MECHANISM mechanism, Template public_key_template, NativeLong public_key_attribute_count, Template private_key_template, NativeLong private_key_attribute_count, LongRef public_key, LongRef private_key);
//        public static native int C_WrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong wrapping_key, NativeLong key, byte[] wrapped_key, LongRef wrapped_key_len);
//        public static native int C_UnwrapKey(NativeLong session, CK_MECHANISM mechanism, NativeLong unwrapping_key, byte[] wrapped_key, NativeLong wrapped_key_len, Template templ, NativeLong attribute_count, LongRef key);
//        public static native int C_DeriveKey(NativeLong session, CK_MECHANISM mechanism, NativeLong base_key, Template templ, NativeLong attribute_count, LongRef key); 
    }
    
    public void testRandom() {
        int session = CE.OpenSession(TESTSLOT);
        byte[] buf = new byte[16];
        CE.SeedRandom(session, buf);
        CE.GenerateRandom(session, buf);
        byte[] buf2 = CE.GenerateRandom(session, 16);
    }

//    public static native int C_GetFunctionStatus(NativeLong session);
//    public static native int C_CancelFunction(NativeLong session);


//    public static native int C_WaitForSlotEvent(NativeLong flags, LongRef slot, Pointer pReserved);
//    public static native int C_GetOperationState(NativeLong session, byte[] operation_state, LongRef operation_state_len);
//    public static native int C_SetOperationState(NativeLong session, byte[] operation_state, NativeLong operation_state_len, NativeLong encryption_key, NativeLong authentication_key);
}
