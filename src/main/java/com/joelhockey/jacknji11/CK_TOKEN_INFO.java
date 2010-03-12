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
 * JNA wrapper for PKCS#11 CK_TOKEN_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_TOKEN_INFO extends Structure {
    public static final int CKF_RNG                   = 0x00000001;
    public static final int CKF_WRITE_PROTECTED       = 0x00000002;
    public static final int CKF_LOGIN_REQUIRED        = 0x00000004;
    public static final int CKF_USER_PIN_INITIALIZED  = 0x00000008;
    public static final int CKF_RESTORE_KEY_NOT_NEEDED=  0x00000020;
    public static final int CKF_CLOCK_ON_TOKEN        =  0x00000040;
    public static final int CKF_PROTECTED_AUTHENTICATION_PATH =0x00000100;
    public static final int CKF_DUAL_CRYPTO_OPERATIONS  =0x00000200;
    public static final int CKF_TOKEN_INITIALIZED       =0x00000400;
    public static final int CKF_SECONDARY_AUTHENTICATION = 0x00000800;
    public static final int CKF_USER_PIN_COUNT_LOW       =0x00010000;
    public static final int CKF_USER_PIN_FINAL_TRY       =0x00020000;
    public static final int CKF_USER_PIN_LOCKED          =0x00040000;
    public static final int CKF_USER_PIN_TO_BE_CHANGED   =0x00080000;
    public static final int CKF_SO_PIN_COUNT_LOW         =0x00100000;
    public static final int CKF_SO_PIN_FINAL_TRY         =0x00200000;
    public static final int CKF_SO_PIN_LOCKED            =0x00400000;
    public static final int CKF_SO_PIN_TO_BE_CHANGED     =0x00800000;

    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.i2s(CK_TOKEN_INFO.class);
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

    public byte[] label = new byte[32];
    public byte[] manufacturerID = new byte[32];
    public byte[] model = new byte[16];
    public byte[] serialNumber = new byte[16];
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
    public CK_VERSION hardwareVersion;
    public CK_VERSION firmwareVersion;
    public byte[] utcTime = new byte[16];
}
