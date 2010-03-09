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
import com.sun.jna.PointerType;

/**
 * Implements a ULONG[] type for JNA.  Allows simple conversion with java int[].
 * JNA direct memory mapping doesn't seem to support struct arrays,
 * so this class is required to map the ints into a contiguous block of memory. 
 * @author Joel Hockey
 */
public class LongArray extends PointerType {
    private int listLen;

    /** Default no-arg constructor required by JNA. */
    public LongArray() {
        this(null);
    }
    
    /**
     * Allocates JNA Memory and writes int values.
     * @param list ints
     */
    public LongArray(int[] list) {
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * NativeLong.SIZE));
        if (NativeLong.SIZE == 4) {
            getPointer().write(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                getPointer().setLong(i, list[i]);
            }
        }
    }

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link Native} that modify
     * ULONG values such as {@link Native#C_FindObjects(NativeLong, LongArray, NativeLong, LongRef)}. 
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     * @param list template
     */
    public void update(int[] list) {
        if (listLen == 0) {
            return;
        }
        if (NativeLong.SIZE == 4) {
            getPointer().read(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                list[i] = (int) getPointer().getLong(i);
            }
        }
    }
}
