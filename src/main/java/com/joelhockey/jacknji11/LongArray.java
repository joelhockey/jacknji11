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
 * Implements a LongArray type for JNA.  Allows simple conversion with int[]. 
 * @author Joel Hockey
 */
public class LongArray extends PointerType {
    private int listLen;

    public LongArray() {
        this(null);
    }
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
