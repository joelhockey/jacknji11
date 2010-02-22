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

public class LongRef extends PointerType {
    public LongRef() {
        this(0);
    }
    public LongRef(int val) {
        setPointer(new Memory(NativeLong.SIZE));
        if (NativeLong.SIZE == 4) {
            getPointer().setInt(0, val);
        } else {
            getPointer().setLong(0, val);
        }
    }
    
    public int val() {
        if (NativeLong.SIZE == 4) {
            return getPointer().getInt(0);
        } else {
            return (int) getPointer().getLong(0);
        }
    }
}
