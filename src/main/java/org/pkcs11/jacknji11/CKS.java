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
 * CKS_? (CK_STATE) constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKS {
    public static final long RO_PUBLIC_SESSION = 0;
    public static final long RO_USER_FUNCTIONS = 1;
    public static final long RW_PUBLIC_SESSION = 2;
    public static final long RW_USER_FUNCTIONS = 3;
    public static final long RW_SO_FUNCTIONS = 4;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = NC.createL2SMap(CKS.class);
    /**
     * Convert long constant value to name.
     * @param cks value
     * @return name
     */
    public static final String L2S(long cks) { return NC.l2s(L2S, CKS.class.getSimpleName(), cks); }
}
