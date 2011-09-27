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
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

import org.pkcs11.jacknji11.CKA;

/**
 * JFFI Wrapper for CK_ATTRIBUTE[].
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class Template {

    public static Pointer templ(CKA[] cka) {
        if (cka == null) {
            return null;
        }
        Runtime runtime = Runtime.getSystemRuntime();
        Pointer result = Memory.allocate(runtime, cka.length * (runtime.longSize() + runtime.addressSize() + runtime.longSize()));

        int offset = 0;
        for (int i = 0; i < cka.length; i++) {
            // type
            result.putLong(offset, cka[i].type);
            offset += runtime.longSize();

            // pValue
            if (cka[i].pValue != null) {
                Pointer pValue = Memory.allocate(runtime, cka[i].pValue.length);
                pValue.put(0, cka[i].pValue, 0, cka[i].pValue.length);
            }
            offset += runtime.addressSize();

            // ulValueLen
            result.putLong(offset, cka[i].ulValueLen);
            offset += runtime.longSize();
        }

        return result;
    }

    public static void update(Pointer templ, CKA[] cka) {
        if (cka == null) {
            return;
        }
        Runtime runtime = Runtime.getSystemRuntime();
        int offset = 0;
        for (int i = 0; i < cka.length; i++) {
            // read ulValueLen (skip type, pValue)
            long ulValueLen = templ.getLong(offset + runtime.longSize() + runtime.addressSize());
            cka[i].ulValueLen = ulValueLen;

            // pValue
            Pointer pValue = templ.getPointer(offset + runtime.longSize());
            pValue.put(0, cka[i].pValue, 0, cka[i].pValue.length);

            // update offset (skip type, pValue, ulValueLen)
            offset += runtime.longSize() + runtime.addressSize() + runtime.longSize();
        }
    }
}
