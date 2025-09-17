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
 * CKP_? constants.
 * https://github.com/oasis-tcs/pkcs11/blob/master/working/headers/pkcs11t.h
 */
public class CKP {
    public static final long CKP_PKCS5_PBKD2_HMAC_SHA1 = 0x00000001;

    public static final long ML_DSA_44           = 0x00000001;
    public static final long ML_DSA_65           = 0x00000002;
    public static final long ML_DSA_87           = 0x00000003;

    /* SLH-DSA values for CKA_PARAMETER_SETS */
    public static final long SLH_DSA_SHA2_128S   = 0x00000001;
    public static final long SLH_DSA_SHAKE_128S  = 0x00000002;
    public static final long SLH_DSA_SHA2_128F   = 0x00000003;
    public static final long SLH_DSA_SHAKE_128F  = 0x00000004;
    public static final long SLH_DSA_SHA2_192S   = 0x00000005;
    public static final long SLH_DSA_SHAKE_192S  = 0x00000006;
    public static final long SLH_DSA_SHA2_192F   = 0x00000007;
    public static final long SLH_DSA_SHAKE_192F  = 0x00000008;
    public static final long SLH_DSA_SHA2_256S   = 0x00000009;
    public static final long SLH_DSA_SHAKE_256S  = 0x0000000a;
    public static final long SLH_DSA_SHA2_256F   = 0x0000000b;
    public static final long SLH_DSA_SHAKE_256F  = 0x0000000c;

    /* ML-KEM values for CKA_PARAMETER_SETS */
    public static final long ML_KEM_512          = 0x00000001;
    public static final long ML_KEM_768          = 0x00000002;
    public static final long ML_KEM_1024         = 0x00000003;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKP.class);
    /**
     * Convert long constant value to name.
     * @param ckp value
     * @return name
     */
    public static final String L2S(long ckp) { return C.l2s(L2S, CKP.class.getSimpleName(), ckp); }
}

