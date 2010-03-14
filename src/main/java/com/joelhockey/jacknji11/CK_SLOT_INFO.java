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

import com.joelhockey.codec.Buf;
import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_SLOT_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_SLOT_INFO extends Structure {

    public static final int CKF_TOKEN_PRESENT    = 0x00000001;
    public static final int CKF_REMOVABLE_DEVICE = 0x00000002;
    public static final int CKF_HW_SLOT          = 0x00000004;

    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.createI2SMap(CK_SLOT_INFO.class);
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

    public byte[] slotDescription = new byte[64];
    public byte[] manufacturerID = new byte[32];
    public NativeLong flags;
    public CK_VERSION hardwareVersion;
    public CK_VERSION firmwareVersion;

    /** @return string */
    public String toString() {
        return String.format("(\n  slotDescription=%s\n  manufacturerID=%s\n  flags=0x%08x{%s}\n  hardwareVersion=%d.%d\n  firmwareVersion=%d.%d\n)",
                Buf.escstr(slotDescription), Buf.escstr(manufacturerID), flags.intValue(), f2s(flags.intValue()),
                hardwareVersion.major & 0xff, hardwareVersion.minor & 0xff,
                firmwareVersion.major & 0xff, firmwareVersion.minor & 0xff);
    }
}
