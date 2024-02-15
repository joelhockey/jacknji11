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

import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CKATest {


    @Test
    public void testAllocate() {
        CKA cka = CKA.allocate(CKA.MODULUS, 100);

        // value is null because the buffer is not really set with anything
        assertNull(cka.getValue());
        assertEquals(100, cka.ulValueLen);
        // however the pValue points at a buffer
        assertNotNull(cka.pValue);

        // it can also be checked by hasValue
        assertFalse(cka.hasValue());

        // to string should not display any value, however it shall display its allocated state
        assertEquals(cka.toString(), "type=0x00000120{MODULUS}  ALLOCATED [100B]");

        // now let's emulate setting the value (this happens when Cryptoki native structure is applied back onto CKA)
        cka.set();

        // value is no longer null
        assertNotNull(cka.getValue());

        // and value is set therfeore hasValue returns true
        assertTrue(cka.hasValue());

        // to string should now display the value and the BUFFERED state shall not be displayed
        assertTrue(cka.toString().contains("type=0x00000120{MODULUS}  [100B]"));

    }

    @Test
    public void testIndefinite() {
        CKA cka = CKA.indefinite(CKA.VALUE);

        // the CKA has no value
        assertNull(cka.getValue());
        // it also does not have a buffer
        assertNull(cka.pValue);
        // and the length is 0
        assertEquals(0, cka.ulValueLen);

        // it can also be checked by hasValue
        assertFalse(cka.hasValue());

        // to string should not display any value, however it shall display its indefinite state
        assertEquals(cka.toString(), "type=0x00000011{VALUE}  INDEFINITE");

        // let's emulate setting the value (this happens when Cryptoki native structure is applied back onto CKA)
        // in this case as buffer is null, only the length is set
        cka.set();
        cka.ulValueLen = 100;

        // value is still null
        assertNull(cka.getValue());

        // but the length is set
        assertEquals(100, cka.ulValueLen);

        // however hasValue still returns false (as there is actually no value set)
        assertFalse(cka.hasValue());

        // to string should now display the length and the INDEFINITE state shall not be displayed
        assertEquals(cka.toString(), cka.toString(), "type=0x00000011{VALUE}  DEFINITE [100B]");

    }

    @Test
    public void testEmpty() {
        // lets create the empty attribute
        CKA cka = new CKA(CKA.VALUE, null);

        // the CKA has no value
        assertNull(cka.getValue());
        // it also does not have a buffer
        assertNull(cka.pValue);
        // and the length is 0
        assertEquals(0, cka.ulValueLen);

        // it can also be checked by hasValue
        assertFalse(cka.hasValue());

        // to string should not display any value, however it shall display its empty state
        assertEquals(cka.toString(), "type=0x00000011{VALUE}  EMPTY");

    }

    @Test
    public void testEmptyFromQuery() {
        // lets create the buffered attribute
        CKA cka = CKA.allocate(CKA.VALUE, 100);

        // now let's set the empty state
        cka.ulValueLen = 0;
        cka.set();

        // the CKA has no value
        assertNull(cka.getValue());

        // and the length is 0
        assertEquals(0, cka.ulValueLen);

        // it can also be checked by hasValue
        assertFalse(cka.hasValue());

        // to string should not display any value, however it shall display its empty state
        assertEquals(cka.toString(), "type=0x00000011{VALUE}  EMPTY");

    }

    @Test
    public void testBool() {
        CKA cka = new CKA(CKA.SENSITIVE, true);

        // we check the encoding
        byte[] bytes = cka.getValue();
        assertArrayEquals(new byte[]{1}, bytes);

        // and the value
        assertTrue(cka.getValueBool());

        // now let's create this attribute from the encoding of value
        CKA cka2 = new CKA(CKA.SENSITIVE, bytes);

        // and check the value
        assertTrue(cka2.getValueBool());

        // and the encoded bytes (should be the same)
        assertArrayEquals(new byte[]{1}, cka2.getValue());

        // also while we have the object let's check the toString
        assertTrue(cka.toString(), cka.toString().contains("type=0x00000103{SENSITIVE}  [1B] value=TRUE"));

        assertEquals(cka, cka2);
        assertEquals(cka.hashCode(), cka2.hashCode());
    }

    @Test
    public void testULong() {
        CKA cka = new CKA(CKA.VALUE_LEN, 100L);
        byte[] expectedBytes = ULong.ulong2b(100L);

        // we check the encoding
        byte[] bytes = cka.getValue();
        assertArrayEquals(expectedBytes, bytes);

        // and the value
        assertEquals(100L, cka.getValueLong().longValue());

        // now let's create this attribute from the encoding of value
        CKA cka2 = new CKA(CKA.VALUE_LEN, bytes);

        // and check the value
        assertEquals(100L, cka2.getValueLong().longValue());

        // and the encoded bytes (should be the same)
        assertArrayEquals(expectedBytes, cka2.getValue());

        // also while we have the object let's check the toString
        assertTrue(cka.toString(), cka.toString().contains("type=0x00000161{VALUE_LEN}  [4B] value=100"));

        assertEquals(cka, cka2);
        assertEquals(cka.hashCode(), cka2.hashCode());
    }


    @Test
    public void testString() {
        String expectedStr = "test";
        byte[] expectedBytes = expectedStr.getBytes(StandardCharsets.US_ASCII);
        CKA cka = new CKA(CKA.LABEL, expectedStr);

        // we check the encoding
        byte[] bytes = cka.getValue();
        assertArrayEquals(expectedBytes, bytes);

        // and the value
        assertEquals(expectedStr, cka.getValueStr());

        // now let's create this attribute from the encoding of value
        CKA cka2 = new CKA(CKA.LABEL, bytes);

        // and check the value
        assertEquals(expectedStr, cka2.getValueStr());

        // and the encoded bytes (should be the same)
        assertArrayEquals(expectedBytes, cka2.getValue());

        // also while we have the object let's check the toString
        assertTrue(cka.toString(), cka.toString().contains("type=0x00000003{LABEL}  [4B] value=\"test\""));

        assertEquals(cka, cka2);
        assertEquals(cka.hashCode(), cka2.hashCode());

    }

    @Test
    public void testBigInt() {

        // the test value is taken directly from PKCS#11 spec
        //        Big integer
        //        a string of CK_BYTEs representing an unsigned integer of arbitrary size,
        //        most-significant byte first (e.g., the integer 32768 is represented as the 2-byte string 0x80 0x00)
        // this encoding when using two-complement encoding in big endian is a negative number
        // therefore needs special handling

        BigInteger expectedBint = BigInteger.valueOf(32768L);
        byte[] expectedBytes = {(byte) 0x80, 0x00};

        // lets create the attribute from value
        CKA cka = new CKA(CKA.MODULUS, expectedBint);

        // we check the encoding
        byte[] bytes = cka.getValue();
        assertArrayEquals(expectedBytes, bytes);

        // and the value
        BigInteger bint = cka.getValueBigInt();
        assertEquals(expectedBint, bint);

        // now let's create this attribute from the encoding of value
        CKA cka2 = new CKA(CKA.MODULUS, bytes);

        // and check the value
        bint = cka2.getValueBigInt();
        assertEquals(expectedBint, bint);

        // and the encoded bytes (should be the same)
        assertArrayEquals(expectedBytes, cka2.getValue());

        // also while we have the object let's check the toString
        assertTrue(cka.toString().contains("type=0x00000120{MODULUS}  [2B]"));
        assertTrue(cka.toString().contains("80 00"));

        assertEquals(cka, cka2);
        assertEquals(cka.hashCode(), cka2.hashCode());
    }


}
