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

import jnr.ffi.Memory;
import jnr.ffi.Struct;

import com.sun.jna.Native;

import org.pkcs11.jacknji11.CKM;

/**
 * JFFI CK_MECHANISM struct wrapper.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CKM extends Struct {
    public long mechanism;
    public jnr.ffi.Pointer pParameter;
    public long ulParameterLen;

    public JFFI_CKM() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }

    public JFFI_CKM readFrom(CKM ckm) {
        mechanism = ckm.mechanism;
        int len = ckm.bParameter != null ? ckm.bParameter.length : 0;
        if (len > 0) {
            pParameter = Memory.allocate(jnr.ffi.Runtime.getSystemRuntime(), len);
            pParameter.put(0, ckm.bParameter, 0, len);
        }
        ulParameterLen = len;
        return this;
    }

    public JFFI_CKM readFromPointer(CKM pMechanism) {
        mechanism = pMechanism.mechanism;
        int len = pMechanism.pParameter != null ? Native.POINTER_SIZE : 0;
        if (len > 0) {
            byte[] ckmParamBytes = pMechanism.pParameter.getByteArray(0, len);
            pParameter = Memory.allocate(jnr.ffi.Runtime.getSystemRuntime(), len);
            pParameter.put(0, ckmParamBytes, 0, len);
        }
        ulParameterLen = len;
        return this;
    }
}
