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

import java.math.BigInteger;
import java.util.Arrays;

import org.pkcs11.jacknji11.Buf;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CE;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKS;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_MECHANISM_INFO;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.Hex;
import org.pkcs11.jacknji11.LongRef;

import junit.framework.TestCase;

/**
 * JUnit tests for jacknji11.
 * Tests all the cryptoki functions that I have ever used and understand.
 * The functions not tested are in commented lines.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CryptokiTest extends TestCase {
    private static final byte[] SO_PIN = "sopin".getBytes();
    private static final byte[] USER_PIN = "userpin".getBytes();
    private static final long TESTSLOT = 0;
    private static final long INITSLOT = 1;

//    private static final long TESTSLOT = 17;
//    private static final long INITSLOT = 18;

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
        long[] slots = CE.GetSlotList(true);
//        System.out.println("slots: " + Arrays.toString(slots));
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
        for (long mech : CE.GetMechanismList(TESTSLOT)) {
//            System.out.println(String.format("0x%08x : %s", mech, CKM.L2S(mech)));
        }
    }

    public void testGetMechanismInfo() {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        CE.GetMechanismInfo(TESTSLOT, CKM.AES_CBC, info);
//        System.out.println(info);
    }

    public void testInitTokenInitPinSetPin() {
        CE.InitToken(INITSLOT, SO_PIN, "TEST".getBytes());
        long session = CE.OpenSession(INITSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.SO, SO_PIN);
        CE.InitPIN(session, USER_PIN);
        CE.Logout(session);
        CE.Login(session, CKU.USER, USER_PIN);
        byte[] somenewpin = "somenewpin".getBytes();
        CE.SetPIN(session, USER_PIN, somenewpin);
        CE.SetPIN(session, somenewpin, USER_PIN);
    }

    public void testGetSessionInfo() {
        long session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CE.GetSessionInfo(session, sessionInfo);
//        System.out.println(sessionInfo);
    }

    public void testGetSessionInfoCloseAllSessions() {
        long s1 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        long s2 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        CE.GetSessionInfo(s2, info );
//        System.out.println(info);
        long s3 = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.CloseSession(s1);
        CE.CloseAllSessions(TESTSLOT);
        assertEquals(CKR.SESSION_HANDLE_INVALID, C.CloseSession(s3));
    }

    public void testGetSetOperationState() {
        long session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        byte[] state = CE.GetOperationState(session);
        CE.SetOperationState(session, state, 0, 0);
    }

    public void testCreateCopyGetSizeDestroyObject() {
        long session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.VALUE, "datavalue"),
        };
        long o1 = CE.CreateObject(session, templ);
        long o2 = CE.CopyObject(session, o1, null);
        CE.DestroyObject(session, o1);
        CE.DestroyObject(session, o2);
    }

    public void testGetObjectSizeGetSetAtt() {
        long session = CE.OpenSession(TESTSLOT);
        CE.Login(session, CKU.USER, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.VALUE, "datavalue"),
        };
        long o = CE.CreateObject(session, templ);
        long size = CE.GetObjectSize(session, o);
        assertNull(CE.GetAttributeValue(session, o, CKA.LABEL).getValueStr());
        assertNull(CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertEquals("datavalue", CE.GetAttributeValue(session, o, CKA.VALUE).getValueStr());
        assertEquals(Long.valueOf(CKO.DATA), CE.GetAttributeValue(session, o, CKA.CLASS).getValueLong());
        assertFalse(CE.GetAttributeValue(session, o, CKA.PRIVATE).getValueBool());
        templ = new CKA[] {
                new CKA(CKA.LABEL, "datalabel"),
                new CKA(CKA.VALUE, "newdatavalue"),
                new CKA(CKA.ID, "dataid"),
        };
        CE.SetAttributeValue(session, o, templ);
        long newsize = CE.GetObjectSize(session, o);
        assertTrue(newsize > size);
        assertEquals("datalabel", CE.GetAttributeValue(session, o, CKA.LABEL).getValueStr());
        assertEquals("dataid", CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertEquals("newdatavalue", CE.GetAttributeValue(session, o, CKA.VALUE).getValueStr());
        assertEquals(Long.valueOf(CKO.DATA), CE.GetAttributeValue(session, o, CKA.CLASS).getValueLong());
        assertFalse(CE.GetAttributeValue(session, o, CKA.PRIVATE).getValueBool());

        templ = CE.GetAttributeValue(session, o, CKA.LABEL, CKA.ID, CKA.VALUE, CKA.CLASS, CKA.PRIVATE);
        assertEquals("datalabel", templ[0].getValueStr());
        assertEquals("dataid", templ[1].getValueStr());
        assertEquals("newdatavalue", templ[2].getValueStr());
        assertEquals(CKO.DATA, templ[3].getValueLong().longValue());
        assertFalse(templ[4].getValueBool());

        templ = CE.GetAttributeValue(session, o, CKA.LABEL, CKA.ID, CKA.OBJECT_ID, CKA.TRUSTED);
        assertEquals("datalabel", templ[0].getValueStr());
        assertEquals("dataid", templ[1].getValueStr());
        assertNull(templ[2].getValue());
        assertNull(templ[3].getValueBool());
    }

    public void testFindObjects() {
        long session = CE.OpenSession(TESTSLOT);
        CE.Login(session, CKU.USER, USER_PIN); // Needed depending on HSM policy
        // create a few objects
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.LABEL, "label1"),
        };
        long o1 = CE.CreateObject(session, templ);
        long o2 = CE.CreateObject(session, templ);
        long o3 = CE.CreateObject(session, templ);
        assertTrue(o1 != o2);
        templ[1] = new CKA(CKA.LABEL, "label2");
        long o4 = CE.CreateObject(session, templ);

        templ = new CKA[] {new CKA(CKA.LABEL, "label1")};
        CE.FindObjectsInit(session, templ);
        assertEquals(2, CE.FindObjects(session, 2).length);
        assertEquals(1, CE.FindObjects(session, 2).length);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
        templ = new CKA[] {new CKA(CKA.LABEL, "label2")};
        CE.FindObjectsInit(session, templ);
        long[] found = CE.FindObjects(session, 2);
        assertEquals(1, found.length);
        assertEquals(o4, found[0]);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
    }


    public void testEncryptDecrypt() {
        long session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);

        long des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.EncryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] plaintext = new byte[10];
        byte[] encrypted1 = CE.EncryptPad(session, plaintext);
        CE.EncryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] encrypted2a = CE.EncryptUpdate(session, new byte[6]);
        byte[] encrypted2b = CE.EncryptUpdate(session, new byte[4]);
        byte[] encrypted2c = CE.EncryptFinal(session);
        assertTrue(Arrays.equals(encrypted1, Buf.cat(encrypted2a, encrypted2b, encrypted2c)));

        CE.DecryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] decrypted1 = CE.DecryptPad(session, encrypted1);
        assertTrue(Arrays.equals(plaintext, decrypted1));
        CE.DecryptInit(session, new CKM(CKM.DES3_CBC_PAD), des3key);
        byte[] decrypted2a = CE.DecryptUpdate(session, Buf.substring(encrypted1, 0, 8));
        byte[] decrypted2b = CE.DecryptUpdate(session, Buf.substring(encrypted1, 8, 8));
        byte[] decrypted2c = CE.DecryptFinal(session);
        assertTrue(Arrays.equals(plaintext, Buf.cat(decrypted2a, decrypted2b, decrypted2c)));
    }

    public void testDigest() {
        long session = CE.OpenSession(TESTSLOT);
        CE.Login(session, CKU.USER, USER_PIN); // Needed depending on HSM policy
        CE.DigestInit(session, new CKM(CKM.SHA256));
        byte[] digested1 = CE.Digest(session, new byte[100]);
        assertEquals(32, digested1.length);
        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestUpdate(session, new byte[50]);
        CE.DigestUpdate(session, new byte[50]);
        byte[] digested2 = CE.DigestFinal(session);
        assertTrue(Arrays.equals(digested1, digested2));

        long des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestKey(session, des3key);
        byte[] digestedKey = CE.DigestFinal(session);
    }

    public void testSignVerify() {
        long session = CE.OpenSession(TESTSLOT);
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
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);

        // TODO: SignUpdate causes JVM crash
//        CE.SignInit(session, new CKM(CKM.RSA_PKCS), privKey.val());
//        CE.SignUpdate(session, new byte[50]);
//        CE.SignUpdate(session, new byte[50]);
//        byte[] sig2 = CE.SignFinal(session);
//        assertTrue(Arrays.equals(sig1, sig2));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.Verify(session, data, sig1);
        assertEquals(CKR.SIGNATURE_INVALID, C.Verify(session, data, new byte[32]));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig1);

        data = new byte[10];
        CE.SignRecoverInit(session, new CKM(CKM.RSA_PKCS), privKey.value());
        byte[] sigrec1 = CE.SignRecover(session, data);
        assertEquals(64, sig1.length);
        CE.VerifyRecoverInit(session, new CKM(CKM.RSA_PKCS), pubKey.value());
        byte[] recdata = CE.VerifyRecover(session, sigrec1);
        assertTrue(Arrays.equals(data, recdata));
    }

//    public static native long C_DigestEncryptUpdate(long session, byte[] part, long part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native long C_DecryptDigestUpdate(long session, byte[] encrypted_part, long encrypted_part_len, byte[] part, LongRef part_len);
//    public static native long C_SignEncryptUpdate(long session, byte[] part, long part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native long C_DecryptVerifyUpdate(long session, byte[] encrypted_part, long encrypted_part_len, byte[] part, LongRef part_len);


    public void testGenerateKeyWrapUnwrap() {
        long session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);

        long des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));
        byte[] des3keybuf = CE.GetAttributeValue(session, des3key, CKA.VALUE).getValue();

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
        final CKA[] pubExpMod = CE.GetAttributeValue(session, pubKey.value(), new long[] {CKA.PUBLIC_EXPONENT, CKA.MODULUS});
//        System.out.println("pubExp: " + Hex.b2s(pubExpMod[0].getValue()));
//        System.out.println("mod   : " + Hex.b2s(pubExpMod[1].getValue()));

        byte[] wrappedDes3 = CE.WrapKey(session, new CKM(CKM.RSA_PKCS), privKey.value(), des3key);

        BigInteger pubExp = new BigInteger(1, pubExpMod[0].getValue());
        BigInteger mod = new BigInteger(1, pubExpMod[1].getValue());
        byte[] unwrappedDes3 = Buf.substring(new BigInteger(1, wrappedDes3).modPow(pubExp, mod).toByteArray(), -24, 24);
//        System.out.println("unwrapped: " + Hex.dump(unwrappedDes3));
        assertTrue(Arrays.equals(des3keybuf, unwrappedDes3));

        long des3key2 = CE.UnwrapKey(session, new CKM(CKM.RSA_PKCS), pubKey.value(), wrappedDes3);
        byte[] des3key2buf = CE.GetAttributeValue(session, des3key2, CKA.VALUE).getValue();
        assertTrue(Arrays.equals(des3key2buf, des3keybuf));

        CE.DeriveKey(session, new CKM(CKM.VENDOR_PTK_DES3_DERIVE_CBC, new byte[32]), des3key);
    }

    public void testRandom() {
        long session = CE.OpenSession(TESTSLOT);
        byte[] buf = new byte[16];
        CE.SeedRandom(session, buf);
        CE.GenerateRandom(session, buf);
        byte[] buf2 = CE.GenerateRandom(session, 16);
    }

//    public static native long C_GetFunctionStatus(long session);
//    public static native long C_CancelFunction(long session);


//    public static native long C_WaitForSlotEvent(long flags, LongRef slot, Pointer pReserved);
//    public static native long C_SetOperationState(long session, byte[] operation_state, long operation_state_len, long encryption_key, long authentication_key);
}
