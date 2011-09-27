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

package org.pkcs11.jacknji11.jna;

import org.pkcs11.jacknji11.CKM;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;


/**
 * CKM_? constants and CK_MECHANISM struct wrapper.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CKM extends Structure {
    public NativeLong mechanism;
    public Pointer pParameter;
    public NativeLong ulParameterLen;

    public JNA_CKM readFrom(CKM ckm) {
        mechanism = new NativeLong(ckm.mechanism);
        int len = ckm.pParameter != null ? ckm.pParameter.length : 0;
        if (len > 0) {
            pParameter = new Memory(len);
            pParameter.write(0, ckm.pParameter, 0, len);
        }
        ulParameterLen = new NativeLong(len);
        return this;
    }
}
