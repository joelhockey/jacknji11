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

/**
 * CKK_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKK {

    public static final int RSA             = 0x00000000;
    public static final int DSA             = 0x00000001;
    public static final int DH              = 0x00000002;
    public static final int EC              = 0x00000003;
    public static final int X9_42_DH        = 0x00000004;
    public static final int KEA             = 0x00000005;
    public static final int GENERIC_SECRET  = 0x00000010;
    public static final int RC2             = 0x00000011;
    public static final int RC4             = 0x00000012;
    public static final int DES             = 0x00000013;
    public static final int DES2            = 0x00000014;
    public static final int DES3            = 0x00000015;
    public static final int CAST            = 0x00000016;
    public static final int CAST3           = 0x00000017;
    public static final int CAST128         = 0x00000018;
    public static final int RC5             = 0x00000019;
    public static final int IDEA            = 0x0000001a;
    public static final int SKIPJACK        = 0x0000001b;
    public static final int BATON           = 0x0000001c;
    public static final int JUNIPER         = 0x0000001d;
    public static final int CDMF            = 0x0000001e;
    public static final int AES             = 0x0000001f;
    public static final int SECURID         = 0x00000022;
    public static final int HOTP            = 0x00000023;
    public static final int ACTI            = 0x00000024;
    public static final int CAMELLIA        = 0x00000025;
    public static final int ARIA            = 0x00000026;


    // Vendor defined values
    // Eracom PTK
    public static final int VENDOR_PTK_RSA_DISCRETE    = 0x80000201;
    public static final int VENDOR_PTK_DSA_DISCRETE    = 0x80000202;
    public static final int VENDOR_PTK_SEED            = 0x80000203;

    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.i2s(CKK.class);
    /**
     * Convert int constant value to name.
     * @param ckk value
     * @return name
     */
    public static final String I2S(int ckk) { return C.i2s(I2S, CKK.class.getSimpleName(), ckk); }
}
