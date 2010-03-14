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
 * JNA wrapper for PKCS#11 CK_INFO struct.  It sets align type to {@link Structure#ALIGN_NONE}
 * since the ULONGS (NativeLongs) dont line up on a 4 byte boundary.  You wouldn't care to know
 * how painful that learning experience was.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_INFO extends Structure {

    /** Maps from int value to String description (variable name). */
    private static final Map<Integer, String> I2S = C.createI2SMap(CK_INFO.class);
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

    public CK_VERSION cryptokiVersion;
    public byte[] manufacturerID = new byte[32];
    public NativeLong flags;
    public byte[] libraryDescription = new byte[32];
    public CK_VERSION libraryVersion;

    /**
     * Default constructor.
     * need to set alignment to none since 'flags' is not
     * correctly aligned to a 4 byte boundary
     */
    public CK_INFO() {
        setAlignType(ALIGN_NONE);
    }

    /** @return string */
    public String toString() {
        return String.format("(\n  version=%d.%d\n  manufacturerID=%s\n  flags=0x%08x{%s}\n  libraryDescription=%s\n  libraryVersion=%d.%d\n)",
                cryptokiVersion.major & 0xff, cryptokiVersion.minor & 0xff, Buf.escstr(manufacturerID),
                flags.intValue(), f2s(flags.intValue()), Buf.escstr(libraryDescription),
                libraryVersion.major & 0xff, libraryVersion.minor & 0xff);

    }
}
