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

package com.joelhockey.jacknji11;

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

        if (NativeLong.SIZE == 4) {
            for (int i = 0; i < listLen; i++) {
                getPointer().setInt(offset, list[i].type);
                offset += 4;
                getPointer().setPointer(offset, list[i].pValue);
                offset += Pointer.SIZE;
                getPointer().setInt(offset, list[i].ulValueLen);
                offset += 4;
            }
        } else {
            for (int i = 0; i < listLen; i++) {
                getPointer().setLong(offset, list[i].type);
                offset += 8;
                getPointer().setPointer(offset, list[i].pValue);
                offset += Pointer.SIZE;
                getPointer().setLong(offset, list[i].ulValueLen);
                offset += 8;
            }
        }

    }

    /** * @return length of template (0 if templ is null) */
    public NativeLong length() { return new NativeLong(listLen); }


    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link Native} that modify CK_ATTRIBUTE struct such as
     * {@link Native#C_GetAttributeValue(NativeLong, NativeLong, Template, NativeLong)}.
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     */
    public void update() {
        if (listLen == 0) {
            return;
        }
        int offset = 0;
        if (NativeLong.SIZE == 4) {
            for (int i = 0; i < list.length; i++) {
                offset += 4 + Pointer.SIZE;
                list[i].ulValueLen = getPointer().getInt(offset);
                offset += 4;
            }
        } else {
            for (int i = 0; i < listLen; i++) {
                offset += 8 + Pointer.SIZE;
                list[i].ulValueLen = (int) getPointer().getLong(offset);
                offset += 8;
            }
        }
    }

    /**
     * Dump for debug.
     * @param sb write to
     */
    public void dump(StringBuilder sb) {
        sb.append("  template (size=").append(listLen).append(')');
        for (int i = 0; i < listLen; i++) {
            sb.append("\n  ");
            list[i].dump(sb);
        }
    }
}
