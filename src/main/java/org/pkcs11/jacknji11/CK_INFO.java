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
 * PKCS#11 CK_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_INFO {

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_INFO.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String L2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }

    public CK_VERSION cryptokiVersion = new CK_VERSION();
    public byte[] manufacturerID = new byte[32];
    public long flags;
    public byte[] libraryDescription = new byte[32];
    public CK_VERSION libraryVersion = new CK_VERSION();

    /** @return string */
    public String toString() {
        return String.format("(\n  version=%d.%d\n  manufacturerID=%s\n  flags=0x%08x{%s}\n  libraryDescription=%s\n  libraryVersion=%d.%d\n)",
                cryptokiVersion.major & 0xff, cryptokiVersion.minor & 0xff, Buf.escstr(manufacturerID),
                flags, f2s(flags), Buf.escstr(libraryDescription),
                libraryVersion.major & 0xff, libraryVersion.minor & 0xff);

    }
}
