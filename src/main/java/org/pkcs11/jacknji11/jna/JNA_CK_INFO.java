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

import org.pkcs11.jacknji11.CK_INFO;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_INFO struct.  It sets align type to {@link Structure#ALIGN_NONE}
 * since the ULONGS (NativeLongs) dont line up on a 4 byte boundary.  You wouldn't care to know
 * how painful that learning experience was.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_INFO extends Structure {

    public JNA_CK_VERSION cryptokiVersion;
    public byte[] manufacturerID;
    public NativeLong flags;
    public byte[] libraryDescription;
    public JNA_CK_VERSION libraryVersion;

    /**
     * Default constructor.
     * need to set alignment to none since 'flags' is not
     * correctly aligned to a 4 byte boundary
     */
    public JNA_CK_INFO() {
        setAlignType(ALIGN_NONE);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("cryptokiVersion", "manufacturerID", "flags", "libraryDescription", "libraryVersion");
    }

    public JNA_CK_INFO readFrom(CK_INFO info) {
        cryptokiVersion = new JNA_CK_VERSION().readFrom(info.cryptokiVersion);
        manufacturerID = info.manufacturerID;
        flags = new NativeLong(info.flags);
        libraryDescription = info.libraryDescription;
        libraryVersion = new JNA_CK_VERSION().readFrom(info.libraryVersion);
        return this;
    }

    public CK_INFO writeTo(CK_INFO info) {
        cryptokiVersion.writeTo(info.cryptokiVersion);
        info.manufacturerID = manufacturerID;
        info.flags = flags.intValue();
        info.libraryDescription = libraryDescription;
        libraryVersion.writeTo(info.libraryVersion);
        return info;
    }
}
