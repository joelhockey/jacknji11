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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * CKO_? constants.
 */
public class CKK {

    public static final int RSA = 0;
    public static final int DSA = 1;
    public static final int DH = 2;
    public static final int ECDSA = 3;
    public static final int EC = 3;
    public static final int X9_42_DH = 4;
    public static final int KEA = 5;
    public static final int GENERIC_SECRET = 16;
    public static final int RC2 = 17;
    public static final int RC4 = 18;
    public static final int RC5 = 25;
    public static final int DES = 19;
    public static final int DES2 = 20;
    public static final int DES3 = 21;
    public static final int CAST = 22;
    public static final int CAST3 = 23;
    public static final int CAST5 = 24;
    public static final int CAST128 = 24;
    public static final int IDEA = 26;
    public static final int SKIPJACK = 27;
    public static final int BATON = 28;
    public static final int JUNIPER = 29;
    public static final int CDMF = 30;
    public static final int AES = 31;
    
    // Vendor defined values
    // Eracom PTK
    public static final int RSA_DISCRETE = 0x80000201;
    public static final int DSA_DISCRETE = 0x80000202;
    public static final int INVALID_VALUE = -1;
    public static final int SEED = 0x80000203;

    /** Maps from int value to String description (variable name). */
    public static final Map<Integer, String> I2S = new HashMap<Integer, String>();
    static {
        try {
            Field[] fields = CKK.class.getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                if (fields[i].getType() == int.class) {
                    I2S.put(fields[i].getInt(null), fields[i].getName());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
