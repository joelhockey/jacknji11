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

import junit.framework.TestCase;

/**
 * JUnit tests for jacknji11.
 * Tests all the cryptoki functions that I have ever used and understand.
 * The functions not tested are in commented lines.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CryptokiTest extends TestCase {
    private byte[] SO_PIN = "sopin".getBytes();
    private byte[] USER_PIN = "userpin".getBytes();
    private long TESTSLOT = 0;
    private long INITSLOT = 1;

    public void setUp() {
        String testSlotEnv = System.getenv("JACKNJI11_TEST_TESTSLOT");
        if (testSlotEnv != null && testSlotEnv.length() > 0) {
            TESTSLOT = Long.parseLong(testSlotEnv);
        }
        String initSlotEnv = System.getenv("JACKNJI11_TEST_INITSLOT");
        if (initSlotEnv != null && initSlotEnv.length() > 0) {
            INITSLOT = Long.parseLong(initSlotEnv);
        }
        String soPinEnv = System.getenv("JACKNJI11_TEST_SO_PIN");
        if (soPinEnv != null && soPinEnv.length() > 0) {
            SO_PIN = soPinEnv.getBytes();
        }
        String userPinEnv = System.getenv("JACKNJI11_TEST_USER_PIN");
        if (userPinEnv != null && userPinEnv.length() > 0) {
            USER_PIN = userPinEnv.getBytes();
        }
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
        long session = CE.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.SO, SO_PIN);
        CE.InitPIN(session, USER_PIN);
        CE.Logout(session);
        CE.Login(session, CKU.USER, USER_PIN);
        byte[] somenewpin = "somenewpin".getBytes();
        CE.SetPIN(session, USER_PIN, somenewpin);
        CE.SetPIN(session, somenewpin, USER_PIN);
    }

    public void testGetSessionInfo() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CE.GetSessionInfo(session, sessionInfo);
//        System.out.println(sessionInfo);
    }

    public void testGetSessionInfoCloseAllSessions() {
        long s1 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        long s2 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        CE.GetSessionInfo(s2, info );
//        System.out.println(info);
        long s3 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.CloseSession(s1);
        CE.CloseAllSessions(TESTSLOT);
        assertEquals(CKR.SESSION_HANDLE_INVALID, C.CloseSession(s3));
    }

    public void testGetSetOperationState() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        byte[] state = CE.GetOperationState(session);
        CE.SetOperationState(session, state, 0, 0);
    }

    public void testCreateCopyGetSizeDestroyObject() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
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
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
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
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
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
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);

        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 32),
                new CKA(CKA.LABEL, "labelencaes"),
                new CKA(CKA.ID, "labelencaes"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.ENCRYPT, true),
                new CKA(CKA.DECRYPT, true),
                new CKA(CKA.DERIVE, true));

        CE.EncryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] plaintext = new byte[10];
        byte[] encrypted1 = CE.EncryptPad(session, plaintext);
        CE.EncryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] encrypted2a = CE.EncryptUpdate(session, new byte[6]);
        byte[] encrypted2b = CE.EncryptUpdate(session, new byte[4]);
        byte[] encrypted2c = CE.EncryptFinal(session);
        assertTrue(Arrays.equals(encrypted1, Buf.cat(encrypted2a, encrypted2b, encrypted2c)));

        CE.DecryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] decrypted1 = CE.DecryptPad(session, encrypted1);
        assertTrue(Arrays.equals(plaintext, decrypted1));
        CE.DecryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] decrypted2a = CE.DecryptUpdate(session, Buf.substring(encrypted1, 0, 8));
        byte[] decrypted2b = CE.DecryptUpdate(session, Buf.substring(encrypted1, 8, 8));
        byte[] decrypted2c = CE.DecryptFinal(session);
        assertTrue(Arrays.equals(plaintext, Buf.cat(decrypted2a, decrypted2b, decrypted2c)));
    }

    public void testDigest() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN); // Needed depending on HSM policy
        CE.DigestInit(session, new CKM(CKM.SHA256));
        byte[] digested1 = CE.Digest(session, new byte[100]);
        assertEquals(32, digested1.length);
        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestUpdate(session, new byte[50]);
        CE.DigestUpdate(session, new byte[50]);
        byte[] digested2 = CE.DigestFinal(session);
        assertTrue(Arrays.equals(digested1, digested2));

        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "labelaesdigest"),
                new CKA(CKA.ID, "labelaesdigest"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestKey(session, aeskey);
        byte[] digestedKey = CE.DigestFinal(session);
    }

    public void testSignVerifyRSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // Different HSMs have a little different requirements on templates, regardless of which are mandatory or not
        // in the P11 spec. To work with as many HSMs as possible, use a good default, as complete as possible, template.
        // On most HSMs you can set CKA_ID after key generations, but some requires adding CKA_ID at generation time
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelrsa-public"),
            new CKA(CKA.ID, "labelrsa"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelrsa-private"),
            new CKA(CKA.ID, "labelrsa"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // Direct sign
        byte[] data = new byte[100];
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.Verify(session, data, sig1);
        
        // Using SignUpdate
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        CE.SignUpdate(session, new byte[50]);
        CE.SignUpdate(session, new byte[50]);
        byte[] sig2 = CE.SignFinal(session);
        assertTrue(Arrays.equals(sig1, sig2));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig2);

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        try {
            CE.Verify(session, data, new byte[128]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
        }
    }

    public void testSignVerifyRSAPSS() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "label-public"),
            new CKA(CKA.ID, "label"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "label-private"),
            new CKA(CKA.ID, "label"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // RSA-PSS needs parameters, which specifies the padding to be used, matching the hash algorithm 
        byte[] params = ULong.ulong2b(new long[]{CKM.SHA256, CKG.MGF1_SHA256, 32});
        CKM ckm = new CKM(CKM.SHA256_RSA_PKCS_PSS, params);

        // Direct sign
        byte[] data = new byte[100];
        CE.SignInit(session, ckm, privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);

        CE.VerifyInit(session, ckm, pubKey.value());
        CE.Verify(session, data, sig1);
        
        // Using SignUpdate
        CE.SignInit(session, ckm, privKey.value());
        CE.SignUpdate(session, new byte[50]);
        CE.SignUpdate(session, new byte[50]);
        byte[] sig2 = CE.SignFinal(session);
        // RSA-PSS uses randomness, so two signatures can not be compared as with RSA PKCS#1
        //assertTrue(Arrays.equals(sig1, sig2));

        CE.VerifyInit(session, ckm, pubKey.value());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig2);

        CE.VerifyInit(session, ckm, pubKey.value());
        try {
            CE.Verify(session, data, new byte[128]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
        }
    }

    public void testSignVerifyECDSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms Specification 
        //   Version 2.40 section 2.3.3 - ECDSA public key objects
        // We use a P-256 key (also known as secp256r1 or prime256v1), the oid 1.2.840.10045.3.1.7 
        //   has DER encoding in Hex 06082a8648ce3d030107
        // DER-encoding of an ANSI X9.62 Parameters, also known as "EC domain parameters".
        //   See X9.62-1998 Public Key Cryptography For The Financial Services Industry: 
        //   The Elliptic Curve Digital Signature Algorithm (ECDSA), page 27.
        byte[] ecCurveParams = Hex.s2b("06082a8648ce3d030107");
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.EC_PARAMS, ecCurveParams),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, false),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelec-public"),
            new CKA(CKA.ID, "labelec"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, false),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelec-private"),
            new CKA(CKA.ID, "labelec"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
        byte[] data = new byte[32]; // SHA256 hash is 32 bytes
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        CE.Verify(session, data, sig1);

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        try {
            CE.Verify(session, data, new byte[64]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
        }
    }

    /** SignRecoverInit and VerifyRecoverInit is not supported on all HSMs, 
     * so it has a separate test that may expect to fail with FUNCTION_NOT_SUPPORTED
     */
    public void testSignVerifyRecoveryRSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // See comments on the method testSignVerifyRSA
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelrsa2-public"),
            new CKA(CKA.ID, "labelrsa2"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelrsa2-private"),
            new CKA(CKA.ID, "labelrsa2"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        byte[] data = new byte[100];
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);

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
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
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
