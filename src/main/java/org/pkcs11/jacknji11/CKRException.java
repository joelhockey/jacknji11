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

/**
 * Exception for CKR values that are non-zero (CKR.OK).
 * Used in {@link CE} interface as alernative to returning
 * CKR for every function.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKRException extends RuntimeException {
    private static final long serialVersionUID = 0x2841de9d258bab8bL;
    private long ckr;

    /**
     * Constructor with CKR value.
     * @param ckr CKR value.
     */
    public CKRException(long ckr) {
        super(String.format("0x%08x: %s", ckr, CKR.L2S(ckr)));
        this.ckr = ckr;
    }

    /**
     * Constructor with message and CKR value.
     * @param msg message
     * @param ckr CKR value
     */
    public CKRException(String msg, long ckr) {
        super(String.format("0x%08x: %s : %s", ckr, CKR.L2S(ckr), msg));
        this.ckr = ckr;
    }

    /** @return CKR value */
    public long getCKR() { return ckr; }
}
