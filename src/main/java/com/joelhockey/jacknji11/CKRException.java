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

/**
 * Exception for CKR values that are non-zero (CKR.OK).
 */
public class CKRException extends RuntimeException {
    private static final long serialVersionUID = 0x2841de9d258bab8bL;
    private int ckr;
    
    public CKRException(int ckr) {
        super(String.format("0x%08x: %s", ckr, CKR.I2S.get(ckr)));
        this.ckr = ckr;
    }
    
    public CKRException(String msg, int ckr) {
        super(String.format("0x%08x: %s : %s", ckr, CKR.I2S.get(ckr), msg));
        this.ckr = ckr;
    }
    
    public int getCKR() { return ckr; }
}
