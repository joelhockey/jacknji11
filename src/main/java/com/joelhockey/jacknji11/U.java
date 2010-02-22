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

public class U {

    public static byte[] cat(byte[]... bufs) {
        int l = 0;
        for (int i = 0; i < bufs.length; i++) {
            l += bufs[i].length;
        }
        
        byte[] result = new byte[l];
        l = 0;
        for (int i = 0; i < bufs.length; i++) {
            System.arraycopy(bufs[i], 0, result, l, bufs[i].length);
            l += bufs[i].length;
        }
        return result;
    }

    public static byte[] i2b(int[] ia) {
        byte[] result = new byte[ia.length * 4];
        int j = 0;
        for (int i = 0; i < ia.length; i++) {
            result[j++] = (byte) (ia[i] >> 24);
            result[j++] = (byte) (ia[i] >> 16);
            result[j++] = (byte) (ia[i] >> 8);
            result[j++] = (byte) ia[i];
        }
        return result;
    }

    public static byte[] i2b(int i) {
        return new byte[] { (byte) (i >> 24), (byte) (i >> 16), (byte) (i >> 8), (byte) i };
    }

    public static byte[] i2bb(int i) {
        return new byte[] { (byte) i, (byte) (i >> 8), (byte) (i >> 16), (byte) (i >> 24) };
    }

    public static void i2b(int i, byte[] buf, int offset) {
        buf[offset++] = (byte) (i >> 24);
        buf[offset++] = (byte) (i >> 16);
        buf[offset++] = (byte) (i >> 8);
        buf[offset++] = (byte) (i);
    }

    public static int b2i(byte[] buf, int start) {
        return (buf[start] & 0xff) << 24 | (buf[start + 1] & 0xff) << 16 | (buf[start + 2] & 0xff) << 8 | (buf[start + 3] & 0xff); 
    }
}
