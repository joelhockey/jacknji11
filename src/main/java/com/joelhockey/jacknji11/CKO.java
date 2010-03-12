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
 * CKO_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKO {

    public static final int DATA                = 0x00000000;
    public static final int CERTIFICATE         = 0x00000001;
    public static final int PUBLIC_KEY          = 0x00000002;
    public static final int PRIVATE_KEY         = 0x00000003;
    public static final int SECRET_KEY          = 0x00000004;
    public static final int HW_FEATURE          = 0x00000005;
    public static final int DOMAIN_PARAMETERS   = 0x00000006;
    public static final int MECHANISM           = 0x00000007;
    public static final int OTP_KEY             = 0x00000008;

    // Vendor defined values
    // Eracom PTK
    public static final int VENDOR_PTK_CERTIFICATE_REQUEST  = 0x80000201;
    public static final int VENDOR_PTK_CRL                  = 0x80000202;
    public static final int VENDOR_PTK_ADAPTER              = 0x8000020a;
    public static final int VENDOR_PTK_SLOT                 = 0x8000020b;
    public static final int VENDOR_PTK_FM                   = 0x8000020c;

    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.i2s(CKO.class);
    /**
     * Convert int constant value to name.
     * @param cko value
     * @return name
     */
    public static final String I2S(int cko) { return C.i2s(I2S, CKO.class.getSimpleName(), cko); }
}
