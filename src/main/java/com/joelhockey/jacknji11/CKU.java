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
 * CKU_? constants.
 */
public class CKU {

    public static final int SO = 0;
    public static final int USER = 1;
    public static final int INVALID_VALUE = -1;

    public static final Map<Integer, String> I2S = new HashMap<Integer, String>();
    static {
        try {
            Field[] fields = CKU.class.getDeclaredFields();
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
