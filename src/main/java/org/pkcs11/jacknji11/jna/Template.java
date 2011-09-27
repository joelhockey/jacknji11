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

import org.pkcs11.jacknji11.CKA;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

/**
 * Wrapper for CK_ATTRIBUTE[] (in this case it is CKA class that represents
 * PKCS#11 CK_ATTRIBUTE struct).  JNA direct memory mapping doesn't seem to
 * support struct arrays, so this class is required to map the
 * list of (type, pValue, ulValueLen) into a contiguous block of memory.
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class Template extends PointerType {
    private CKA[] list;
    private int listLen;

    /** Default no-arg constructor required by JNA. */
    public Template() {
        this(null);
    }

    /**
     * Allocates JNA Memory and writes CKA[] values.
     * @param list template
     */
    public Template(CKA[] list) {
        this.list = list;
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * (NativeLong.SIZE + Pointer.SIZE + NativeLong.SIZE)));
        int offset = 0;

        for (int i = 0; i < listLen; i++) {
            // type
            if (NativeLong.SIZE == 4) {
                getPointer().setInt(offset, (int) list[i].type);
            } else {
                getPointer().setLong(offset, list[i].type);
            }
            offset += NativeLong.SIZE;

            // pValue
            Memory pValue = null;
            if (list[i].ulValueLen > 0) {
                pValue = new Memory(list[i].ulValueLen);
                pValue.write(0, list[i].pValue, 0, (int) list[i].ulValueLen);
            }
            getPointer().setPointer(offset, pValue);
            offset += Pointer.SIZE;

            // ulValueLen
            if (NativeLong.SIZE == 4) {
                getPointer().setInt(offset, (int) list[i].ulValueLen);
            } else {
                getPointer().setLong(offset, list[i].ulValueLen);
            }
            offset += NativeLong.SIZE;
        }
    }

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link NativeProvider} that modify CK_ATTRIBUTE struct such as
     * {@link NativeProvider#C_GetAttributeValue(NativeLong, NativeLong, Template, NativeLong)}.
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     */
    public void update() {
        if (listLen == 0) {
            return;
        }
        int offset = 0;
        for (int i = 0; i < list.length; i++) {
            offset += NativeLong.SIZE; // skip type

            // read pValue
            Pointer ptr = getPointer().getPointer(offset);
            offset += Pointer.SIZE;

            // read ulValueLen
            int ulValueLen = 0;
            if (NativeLong.SIZE == 4) {
                ulValueLen = getPointer().getInt(offset);
            } else {
                ulValueLen = (int) getPointer().getLong(offset);
            }
            offset += NativeLong.SIZE;

            // read contents into pValue if ptr != null && ulValueLen > 0
            if (ptr != null && ulValueLen > 0) {
                ptr.read(0, list[i].pValue, 0, ulValueLen);
            }
            list[i].ulValueLen = ulValueLen;
        }
    }
}
