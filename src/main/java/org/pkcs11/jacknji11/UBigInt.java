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

/**
 * Utility class for encoding and decoding unsigned big integers in big-endian byte arrays.
 * <p>
 * Unsigned big integers are encoded as big-endian byte arrays without leading zero bytes.
 *
 * @author Tomasz Wysocki
 */
public class UBigInt {

    private UBigInt() {
        // utility class
    }

    /**
     * Encode unsigned big integer to byte array.
     *
     * @param value unsigned big integer
     * @return byte array with big-endian encoding without leading zero bytes,
     * the size of the array is the minimum required to represent the value.
     */
    public static byte[] ubigint2b(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // strip initial zero if present as we are operating on unsigned values
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    /**
     * Decode unsigned big integer from byte array.
     *
     * @param bytes byte array with big-endian encoding of unsigned big integer (highest bit is not a sign bit)
     * @return unsigned big integer
     */
    public static BigInteger b2ubigint(byte[] bytes) {
        return new BigInteger(1, bytes);
    }
}
