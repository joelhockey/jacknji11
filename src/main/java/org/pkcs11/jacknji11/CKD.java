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

import java.util.Map;

/**
 * CKD_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKD {
    public static final long NULL                    = 0x00000001;
    public static final long SHA1_KDF                = 0x00000002;
    public static final long SHA1_KDF_ASN1           = 0x00000003;
    public static final long SHA1_KDF_CONCATENATE    = 0x00000004;
    public static final long SHA224_KDF              = 0x00000005;
    public static final long SHA256_KDF              = 0x00000006;
    public static final long SHA384_KDF              = 0x00000007;
    public static final long SHA512_KDF              = 0x00000008;
    public static final long CPDIVERSIFY_KDF         = 0x00000009;
    public static final long SHA3_224_KDF            = 0x0000000A;
    public static final long SHA3_256_KDF            = 0x0000000B;
    public static final long SHA3_384_KDF            = 0x0000000C;
    public static final long SHA3_512_KDF            = 0x0000000D;
    public static final long SHA1_KDF_SP800          = 0x0000000E;
    public static final long SHA224_KDF_SP800        = 0x0000000F;
    public static final long SHA256_KDF_SP800        = 0x00000010;
    public static final long SHA384_KDF_SP800        = 0x00000011;
    public static final long SHA512_KDF_SP800        = 0x00000012;
    public static final long SHA3_224_KDF_SP800      = 0x00000013;
    public static final long SHA3_256_KDF_SP800      = 0x00000014;
    public static final long SHA3_384_KDF_SP800      = 0x00000015;
    public static final long SHA3_512_KDF_SP800      = 0x00000016;
    public static final long BLAKE2B_160_KDF         = 0x00000017;
    public static final long BLAKE2B_256_KDF         = 0x00000018;
    public static final long BLAKE2B_384_KDF         = 0x00000019;
    public static final long BLAKE2B_512_KDF         = 0x0000001a;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKD.class);
    /**
     * Convert long constant value to name.
     * @param ckd value
     * @return name
     */
    public static final String L2S(long ckd) { return C.l2s(L2S, CKD.class.getSimpleName(), ckd); }
}
