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

import org.pkcs11.jacknji11.CK_TOKEN_INFO;

/**
 * JFFI wrapper for PKCS#11 CK_TOKEN_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_TOKEN_INFO extends Struct {
    public byte[] label;
    public byte[] manufacturerID;
    public byte[] model;
    public byte[] serialNumber;
    public long flags;
    public long ulMaxSessionCount;
    public long ulSessionCount;
    public long ulMaxRwSessionCount;
    public long ulRwSessionCount;
    public long ulMaxPinLen;
    public long ulMinPinLen;
    public long ulTotalPublicMemory;
    public long ulFreePublicMemory;
    public long ulTotalPrivateMemory;
    public long ulFreePrivateMemory;
    public JFFI_CK_VERSION hardwareVersion;
    public JFFI_CK_VERSION firmwareVersion;
    public byte[] utcTime;

    public JFFI_CK_TOKEN_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }


    public JFFI_CK_TOKEN_INFO readFrom(CK_TOKEN_INFO info) {
        label = info.label;
        manufacturerID = info.manufacturerID;
        model = info.model;
        serialNumber = info.serialNumber;
        flags = info.flags;
        ulMaxSessionCount = info.ulMaxSessionCount;
        ulSessionCount = info.ulSessionCount;
        ulMaxRwSessionCount = info.ulMaxRwSessionCount;
        ulRwSessionCount = info.ulRwSessionCount;
        ulMaxPinLen = info.ulMaxPinLen;
        ulMinPinLen = info.ulMinPinLen;
        ulTotalPublicMemory = info.ulTotalPublicMemory;
        ulFreePublicMemory = info.ulFreePublicMemory;
        ulTotalPrivateMemory = info.ulTotalPrivateMemory;
        ulFreePrivateMemory = info.ulFreePrivateMemory;
        hardwareVersion = new JFFI_CK_VERSION().readFrom(info.hardwareVersion);
        firmwareVersion = new JFFI_CK_VERSION().readFrom(info.firmwareVersion);
        utcTime = info.utcTime;
        return this;
    }

    public CK_TOKEN_INFO writeTo(CK_TOKEN_INFO info) {
        info.label = label;
        info.manufacturerID = manufacturerID;
        info.model = model;
        info.serialNumber = serialNumber;
        info.flags = flags;
        info.ulMaxSessionCount = ulMaxSessionCount;
        info.ulSessionCount = ulSessionCount;
        info.ulMaxRwSessionCount = ulMaxRwSessionCount;
        info.ulRwSessionCount = ulRwSessionCount;
        info.ulMaxPinLen = ulMaxPinLen;
        info.ulMinPinLen = ulMinPinLen;
        info.ulTotalPublicMemory = ulTotalPublicMemory;
        info.ulFreePublicMemory = ulFreePublicMemory;
        info.ulTotalPrivateMemory = ulTotalPrivateMemory;
        info.ulFreePrivateMemory = ulFreePrivateMemory;
        hardwareVersion.writeTo(info.hardwareVersion);
        firmwareVersion.writeTo(info.firmwareVersion);
        info.utcTime = utcTime;
        return info;
    }
}
