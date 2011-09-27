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

import org.pkcs11.jacknji11.CK_TOKEN_INFO;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_TOKEN_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_TOKEN_INFO extends Structure {
    public byte[] label;
    public byte[] manufacturerID;
    public byte[] model;
    public byte[] serialNumber;
    public NativeLong flags;
    public NativeLong ulMaxSessionCount;
    public NativeLong ulSessionCount;
    public NativeLong ulMaxRwSessionCount;
    public NativeLong ulRwSessionCount;
    public NativeLong ulMaxPinLen;
    public NativeLong ulMinPinLen;
    public NativeLong ulTotalPublicMemory;
    public NativeLong ulFreePublicMemory;
    public NativeLong ulTotalPrivateMemory;
    public NativeLong ulFreePrivateMemory;
    public JNA_CK_VERSION hardwareVersion;
    public JNA_CK_VERSION firmwareVersion;
    public byte[] utcTime;

    public JNA_CK_TOKEN_INFO readFrom(CK_TOKEN_INFO info) {
        label = info.label;
        manufacturerID = info.manufacturerID;
        model = info.model;
        serialNumber = info.serialNumber;
        flags = new NativeLong(info.flags);
        ulMaxSessionCount = new NativeLong(info.ulMaxSessionCount);
        ulSessionCount = new NativeLong(info.ulSessionCount);
        ulMaxRwSessionCount = new NativeLong(info.ulMaxRwSessionCount);
        ulRwSessionCount = new NativeLong(info.ulRwSessionCount);
        ulMaxPinLen = new NativeLong(info.ulMaxPinLen);
        ulMinPinLen = new NativeLong(info.ulMinPinLen);
        ulTotalPublicMemory = new NativeLong(info.ulTotalPublicMemory);
        ulFreePublicMemory = new NativeLong(info.ulFreePublicMemory);
        ulTotalPrivateMemory = new NativeLong(info.ulTotalPrivateMemory);
        ulFreePrivateMemory = new NativeLong(info.ulFreePrivateMemory);
        hardwareVersion = new JNA_CK_VERSION().readFrom(info.hardwareVersion);
        firmwareVersion = new JNA_CK_VERSION().readFrom(info.firmwareVersion);
        utcTime = info.utcTime;
        return this;
    }

    public CK_TOKEN_INFO writeTo(CK_TOKEN_INFO info) {
        info.label = label;
        info.manufacturerID = manufacturerID;
        info.model = model;
        info.serialNumber = serialNumber;
        info.flags = flags.intValue();
        info.ulMaxSessionCount = ulMaxSessionCount.intValue();
        info.ulSessionCount = ulSessionCount.intValue();
        info.ulMaxRwSessionCount = ulMaxRwSessionCount.intValue();
        info.ulRwSessionCount = ulRwSessionCount.intValue();
        info.ulMaxPinLen = ulMaxPinLen.intValue();
        info.ulMinPinLen = ulMinPinLen.intValue();
        info.ulTotalPublicMemory = ulTotalPublicMemory.intValue();
        info.ulFreePublicMemory = ulFreePublicMemory.intValue();
        info.ulTotalPrivateMemory = ulTotalPrivateMemory.intValue();
        info.ulFreePrivateMemory = ulFreePrivateMemory.intValue();
        hardwareVersion.writeTo(info.hardwareVersion);
        firmwareVersion.writeTo(info.firmwareVersion);
        info.utcTime = utcTime;
        return info;
    }
}
