/* 
 * Copyright 2010 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 * THIS SOURCE CODE IS PROVIDED BY JOEL HOCKEY WITH A 30-DAY MONEY BACK
 * GUARANTEE.  IF THIS CODE DOES NOT MEAN WHAT IT SAYS IT MEANS WITHIN THE
 * FIRST 30 DAYS, SIMPLY RETURN THIS CODE IN ORIGINAL CONDITION FOR A PARTIAL
 * REFUND.  IN ADDITION, I WILL REFORMAT THIS CODE USING YOUR PREFERRED
 * BRACE-POSITIONING AND INDENTATION.  THIS WARRANTY IS VOID IF THE CODE IS
 * FOUND TO HAVE BEEN COMPILED.  NO FURTHER WARRANTY IS OFFERED.
 */

package com.joelhockey.jacknji11;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.NativeLongByReference;
import com.joelhockey.codec.Hex;

public class CK_ATTRIBUTE {
    public int type;
    public Pointer pValue;
    public int ulValueLen;

    private CK_ATTRIBUTE() {
    }

    public CK_ATTRIBUTE(int type, Object value) {
        this.type = type;
        if (value == null) {
            pValue = null;
            ulValueLen = 0;
        } else if (value instanceof Boolean) {
            pValue = new ByteByReference((Boolean) value ? (byte) 1 : (byte) 0).getPointer();
            ulValueLen = 1;
        } else if (value instanceof byte[]) {
            byte[] v = (byte[]) value;
            pValue = new Memory(v.length);
            pValue.write(0, v, 0, v.length);
            ulValueLen = v.length;
        } else if (value instanceof Number) {
            pValue = new NativeLongByReference(new NativeLong(((Number) value).longValue())).getPointer();
            ulValueLen = NativeLong.SIZE;
        } else if (value instanceof String) {
            byte[] v = ((String) value).getBytes();
            pValue = new Memory(v.length);
            pValue.write(0, v, 0, v.length);
            ulValueLen = v.length;
        } else {
            throw new RuntimeException("Unknown type: " + pValue.getClass());
        }
    }
    
    public byte[] getValue() { return pValue == null ? null : pValue.getByteArray(0, ulValueLen); }
    public String getValueStr() { return pValue == null ? null : new String(pValue.getByteArray(0, ulValueLen)); }
    public int getValueInt() {
        if (ulValueLen != NativeLong.SIZE) {
            throw new IllegalStateException(String.format(
                    "Method getValueInt called when value is not int type of length %d.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                    NativeLong.SIZE, ulValueLen, type, CKA.I2S.get(type), Hex.b2s(getValue())));
        }
        return NativeLong.SIZE == 4 ? pValue.getInt(0) : (int) pValue.getLong(0);
    }
    public boolean getValueBool() { 
        if (ulValueLen != 1) {
            throw new IllegalStateException(String.format(
                    "Method getValueBool called when value is not boolean type of length 1.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                    ulValueLen, type, CKA.I2S.get(type), Hex.b2s(getValue())));
        }
        return pValue.getByte(0) != 0;
    }
}
