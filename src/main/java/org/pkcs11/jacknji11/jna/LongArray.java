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

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.PointerType;

/**
 * Implements a CK_ULONG[] type for JNA.  Allows simple conversion with java long[].
 * JNA direct memory mapping doesn't seem to support struct arrays,
 * so this class is required to map the ints into a contiguous block of memory.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class LongArray extends PointerType {
    private long[] list;
    private int listLen;

    /** Default no-arg constructor required by JNA. */
    public LongArray() {
        this(null);
    }

    /**
     * Allocates JNA Memory and writes long values.
     * @param list longs
     */
    public LongArray(long[] list) {
        this.list = list;
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * NativeLong.SIZE));
        if (NativeLong.SIZE == 8) {
            getPointer().write(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                getPointer().setInt(i, (int) list[i]);
            }
        }
    }

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link NativeProvider} that modify
     * ULONG values such as {@link NativeProvider#C_FindObjects(NativeLong, LongArray, NativeLong, LongRef)}.
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     */
    public void update() {
        if (listLen == 0) {
            return;
        }
        if (NativeLong.SIZE == 8) {
            getPointer().read(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                list[i] = getPointer().getInt(i * NativeLong.SIZE);
            }
        }
    }
}
