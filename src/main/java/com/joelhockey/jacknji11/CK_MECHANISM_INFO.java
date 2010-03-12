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

import java.util.Map;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_MECHANSIM_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_MECHANISM_INFO extends Structure {
    public static final int CKF_ENCRYPT             = 0x00000100;
    public static final int CKF_DECRYPT             = 0x00000200;
    public static final int CKF_DIGEST              = 0x00000400;
    public static final int CKF_SIGN                = 0x00000800;
    public static final int CKF_SIGN_RECOVER        = 0x00001000;
    public static final int CKF_VERIFY              = 0x00002000;
    public static final int CKF_VERIFY_RECOVER      = 0x00004000;
    public static final int CKF_GENERATE            = 0x00008000;
    public static final int CKF_GENERATE_KEY_PAIR   = 0x00010000;
    public static final int CKF_WRAP                = 0x00020000;
    public static final int CKF_UNWRAP              = 0x00040000;
    public static final int CKF_DERIVE              = 0x00080000;
    public static final int CKF_EC_F_P              = 0x00100000;
    public static final int CKF_EC_F_2M             = 0x00200000;
    public static final int CKF_EC_ECPARAMETERS     = 0x00400000;
    public static final int CKF_EC_NAMEDCURVE       = 0x00800000;
    public static final int CKF_EC_UNCOMPRESS       = 0x01000000;
    public static final int CKF_EC_COMPRESS         = 0x02000000;
    public static final int CKF_EXTENSION           = 0x80000000;


    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.i2s(CK_MECHANISM_INFO.class);
    /**
     * Convert int constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String I2S(int ckf) { return C.i2s(I2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(int flags) { return C.f2s(I2S, flags); }


    public NativeLong ulMinKeySize;
    public NativeLong ulMaxKeySize;
    public NativeLong flags;
}
