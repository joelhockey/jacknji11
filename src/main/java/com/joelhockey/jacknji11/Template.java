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
import com.sun.jna.PointerType;

/**
 * Wrapper for CK_ATTRIBUTE[] (in this case it is CKA class that represents
 * PKCS#11 CK_ATTRIBUTE struct).  JNA direct memory mapping doesn't seem to
 * support struct arrays, so this class is required to map the 
 * list of (type, pValue, ulValueLen) into a contiguous block of memory.
 *  
 * @author Joel Hockey
 */
public class Template extends PointerType {
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

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link Native} that modify CK_ATTRIBUTE struct such as 
     * {@link Native#C_GetAttributeValue(NativeLong, NativeLong, Template, NativeLong)}.
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     * @param list template
     */
    public void update(CKA[] list) {
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
}
