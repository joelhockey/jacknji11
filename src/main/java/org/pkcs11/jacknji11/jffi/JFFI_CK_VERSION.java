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

package org.pkcs11.jacknji11.jffi;

import jnr.ffi.Struct;

import org.pkcs11.jacknji11.CK_VERSION;

/**
 * JFFI wrapper for PKCS#11 CK_VERSION.  It hardly seems worthwhile
 * wrapping 2 bytes, but we have.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_VERSION extends Struct {
    public byte major;
    public byte minor;

    public JFFI_CK_VERSION() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }

    public JFFI_CK_VERSION readFrom(CK_VERSION version) {
        major = version.major;
        minor = version.minor;
        return this;
    }
    public CK_VERSION writeTo(CK_VERSION version) {
        version.major = major;
        version.minor = minor;
        return version;
    }
}
