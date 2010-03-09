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

import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.TestCase;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;

/**
 * JUnit tests for jacknji11.
 * Tests all the cryptoki functions that I have ever used and understand.
 * The functions not tested are in commented lines.
 * @author Joel Hockey
 */
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
        assertEquals(2, CE.FindObjects(session, 2).length);
        assertEquals(1, CE.FindObjects(session, 2).length);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
        templ = new CKA[] {new CKA(CKA.LABEL, "label2")};
        CE.FindObjectsInit(session, templ);
        int[] found = CE.FindObjects(session, 2);
        assertEquals(1, found.length);
        assertEquals(o4, found[0]);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
    }
    

    public void testEncryptDecrypt() {
        int session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);
        
        int des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.EncryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] plaintext = new byte[10];
        byte[] encrypted1 = CE.Encrypt(session, plaintext);
        CE.EncryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] encrypted2a = CE.EncryptUpdate(session, new byte[6]);
        byte[] encrypted2b = CE.EncryptUpdate(session, new byte[4]);
        byte[] encrypted2c = CE.EncryptFinal(session);
        assertTrue(Arrays.equals(encrypted1, Buf.cat(encrypted2a, encrypted2b, encrypted2c)));

        CE.DecryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] decrypted1 = CE.Decrypt(session, encrypted1);
        assertTrue(Arrays.equals(plaintext, decrypted1));
        CE.DecryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] decrypted2a = CE.DecryptUpdate(session, Buf.substring(encrypted1, 0, 8));
        byte[] decrypted2b = CE.DecryptUpdate(session, Buf.substring(encrypted1, 8, 8));
        byte[] decrypted2c = CE.DecryptFinal(session);
        assertTrue(Arrays.equals(plaintext, Buf.cat(decrypted2a, decrypted2b, decrypted2c)));
    }

    public void testDigest() {
        int session = CE.OpenSession(TESTSLOT);
        CE.DigestInit(session, new CKM(CKM.SHA256));
        byte[] digested1 = CE.Digest(session, new byte[100]);
        assertEquals(32, digested1.length);
        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestUpdate(session, new byte[50]);
        CE.DigestUpdate(session, new byte[50]);
        byte[] digested2 = CE.DigestFinal(session);
        assertTrue(Arrays.equals(digested1, digested2));
        
        int des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestKey(session, des3key);
        byte[] digestedKey = CE.DigestFinal(session);
    }

    public void testSignVerify() {
        int session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 512),
            new CKA(CKA.UNWRAP, true),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.VERIFY, true),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.SIGN, true),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        byte[] data = new byte[100];
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.val());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);

        // TODO: SignUpdate causes JVM crash
//        CE.SignInit(session, new CKM(CKM.RSA_PKCS), privKey.val());
//        CE.SignUpdate(session, new byte[50]);
//        CE.SignUpdate(session, new byte[50]);
//        byte[] sig2 = CE.SignFinal(session);
//        assertTrue(Arrays.equals(sig1, sig2));
        
        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.val());
        CE.Verify(session, data, sig1);
        assertEquals(CKR.SIGNATURE_INVALID, C.Verify(session, data, new byte[32]));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.val());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig1);

        data = new byte[10];
        CE.SignRecoverInit(session, new CKM(CKM.RSA_PKCS), privKey.val());
        byte[] sigrec1 = CE.SignRecover(session, data);
        assertEquals(64, sig1.length);
        CE.VerifyRecoverInit(session, new CKM(CKM.RSA_PKCS), pubKey.val());
        byte[] recdata = CE.VerifyRecover(session, sigrec1);
        assertTrue(Arrays.equals(data, recdata));
    }

//    public static native int C_DigestEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native int C_DecryptDigestUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
//    public static native int C_SignEncryptUpdate(NativeLong session, byte[] part, NativeLong part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native int C_DecryptVerifyUpdate(NativeLong session, byte[] encrypted_part, NativeLong encrypted_part_len, byte[] part, LongRef part_len);
  
    
    public void testGenerateKeyWrapUnwrap() {
        int session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);
        
        int des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));
        byte[] des3keybuf = CE.GetAttributeValueBuf(session, des3key, CKA.VALUE);
        
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 512),
            new CKA(CKA.UNWRAP, true),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.WRAP, true),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        final CKA[] pubExpMod = CE.GetAttributeValue(session, pubKey.val(), new int[] {CKA.PUBLIC_EXPONENT, CKA.MODULUS});
        System.out.println("pubExp: " + Hex.b2s(pubExpMod[0].getValue()));
        System.out.println("mod   : " + Hex.b2s(pubExpMod[1].getValue()));
        
        byte[] wrappedDes3 = CE.WrapKey(session, new CKM(CKM.RSA_PKCS), privKey.val(), des3key);

        BigInteger pubExp = new BigInteger(1, pubExpMod[0].getValue());
        BigInteger mod = new BigInteger(1, pubExpMod[1].getValue());
        byte[] unwrappedDes3 = Buf.substring(new BigInteger(1, wrappedDes3).modPow(pubExp, mod).toByteArray(), -24, 24);
        System.out.println("unwrapped: " + Hex.dump(unwrappedDes3));
        assertTrue(Arrays.equals(des3keybuf, unwrappedDes3));

        int des3key2 = CE.UnwrapKey(session, new CKM(CKM.RSA_PKCS), pubKey.val(), wrappedDes3);
        byte[] des3key2buf = CE.GetAttributeValueBuf(session, des3key2, CKA.VALUE);
        assertTrue(Arrays.equals(des3key2buf, des3keybuf));
        
        CE.DeriveKey(session, new CKM(CKM.VENDOR_PTK_DES3_DERIVE_CBC, new byte[32]), des3key);
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
