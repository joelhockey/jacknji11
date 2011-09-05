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
import com.sun.jna.PointerType;

/**
 * JNA wrapper for ULONG.  It is exactly like NativeLong except that I didn't
 * like having JNA namespaces all through application code and I like typing
 * 'val()' better than 'intValue()'.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class LongRef extends PointerType {
    /** Defalult constructor sets to zero. */
    public LongRef() {
        this(0);
    }
    /**
     * Constructor taking java int.  Allocates JNA Memory object
     * using NativeLong.SIZE and sets to this value.
     * @param val value
     */
    public LongRef(int val) {
        setPointer(new Memory(NativeLong.SIZE));
        if (NativeLong.SIZE == 4) {
            getPointer().setInt(0, val);
        } else {
            getPointer().setLong(0, val);
        }
    }

    /** @return current value from JNA Memory object */
    public int val() {
        if (NativeLong.SIZE == 4) {
            return getPointer().getInt(0);
        } else {
            return (int) getPointer().getLong(0);
        }
    }
}
