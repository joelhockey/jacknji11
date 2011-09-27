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
 * PKCS#11 CK_MECHANSIM_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_MECHANISM_INFO {
    public static final long CKF_HW                  = 0x00000001;
    public static final long CKF_ENCRYPT             = 0x00000100;
    public static final long CKF_DECRYPT             = 0x00000200;
    public static final long CKF_DIGEST              = 0x00000400;
    public static final long CKF_SIGN                = 0x00000800;
    public static final long CKF_SIGN_RECOVER        = 0x00001000;
    public static final long CKF_VERIFY              = 0x00002000;
    public static final long CKF_VERIFY_RECOVER      = 0x00004000;
    public static final long CKF_GENERATE            = 0x00008000;
    public static final long CKF_GENERATE_KEY_PAIR   = 0x00010000;
    public static final long CKF_WRAP                = 0x00020000;
    public static final long CKF_UNWRAP              = 0x00040000;
    public static final long CKF_DERIVE              = 0x00080000;
    public static final long CKF_EC_F_P              = 0x00100000;
    public static final long CKF_EC_F_2M             = 0x00200000;
    public static final long CKF_EC_ECPARAMETERS     = 0x00400000;
    public static final long CKF_EC_NAMEDCURVE       = 0x00800000;
    public static final long CKF_EC_UNCOMPRESS       = 0x01000000;
    public static final long CKF_EC_COMPRESS         = 0x02000000;
    public static final long CKF_EXTENSION           = 0x80000000;


    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_MECHANISM_INFO.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String I2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }


    public long ulMinKeySize;
    public long ulMaxKeySize;
    public long flags;

    /** @return string */
    public String toString() {
        return String.format("(\n  minKeySize=%d\n  maxKeySize=%d\n  flags=0x%08x{%s}\n)",
                ulMinKeySize, ulMaxKeySize, flags, f2s(flags));

    }
}
