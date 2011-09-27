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
 * CKK_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKK {

    public static final long RSA             = 0x00000000;
    public static final long DSA             = 0x00000001;
    public static final long DH              = 0x00000002;
    public static final long EC              = 0x00000003;
    public static final long X9_42_DH        = 0x00000004;
    public static final long KEA             = 0x00000005;
    public static final long GENERIC_SECRET  = 0x00000010;
    public static final long RC2             = 0x00000011;
    public static final long RC4             = 0x00000012;
    public static final long DES             = 0x00000013;
    public static final long DES2            = 0x00000014;
    public static final long DES3            = 0x00000015;
    public static final long CAST            = 0x00000016;
    public static final long CAST3           = 0x00000017;
    public static final long CAST128         = 0x00000018;
    public static final long RC5             = 0x00000019;
    public static final long IDEA            = 0x0000001a;
    public static final long SKIPJACK        = 0x0000001b;
    public static final long BATON           = 0x0000001c;
    public static final long JUNIPER         = 0x0000001d;
    public static final long CDMF            = 0x0000001e;
    public static final long AES             = 0x0000001f;
    public static final long SECURID         = 0x00000022;
    public static final long HOTP            = 0x00000023;
    public static final long ACTI            = 0x00000024;
    public static final long CAMELLIA        = 0x00000025;
    public static final long ARIA            = 0x00000026;


    // Vendor defined values
    // Eracom PTK
    public static final long VENDOR_PTK_RSA_DISCRETE    = 0x80000201L;
    public static final long VENDOR_PTK_DSA_DISCRETE    = 0x80000202L;
    public static final long VENDOR_PTK_SEED            = 0x80000203L;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKK.class);
    /**
     * Convert long constant value to name.
     * @param ckk value
     * @return name
     */
    public static final String L2S(long ckk) { return C.l2s(L2S, CKK.class.getSimpleName(), ckk); }
}
