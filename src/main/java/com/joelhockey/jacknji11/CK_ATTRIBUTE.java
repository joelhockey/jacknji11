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
import com.sun.jna.Structure;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.NativeLongByReference;

public class CK_ATTRIBUTE extends Structure {
    public int type;
    public Pointer pValue;
    public int ulValueLen;

    public CK_ATTRIBUTE() {
    }

    public CK_ATTRIBUTE(int type, Object value) {
        this.type = type;
        if (value == null) {
            pValue = new Memory(0);
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
            throw new RuntimeException("Unknown type for template: " + pValue.getClass());
        }
        
        System.out.println("att: type: " + CKA.I2S.get(type) + ", valLen: " + ulValueLen);
    }
}
