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

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_INFO struct.  It sets align type to {@link Structure#ALIGN_NONE}
 * since the ULONGS (NativeLongs) dont line up on a 4 byte boundary.  You wouldn't care to know
 * how painful that learning experience was.
 * @author Joel Hockey
 */
public class CK_INFO extends Structure {
    public CK_VERSION cryptokiVersion;
    public byte[] manufacturerID = new byte[32];
    public NativeLong flags;
    public byte[] libraryDescription = new byte[32];
    public CK_VERSION libraryVersion;

    // need to set alignment to none since 'flags' is not
    // correctly aligned to a 4 byte boundary
    public CK_INFO() {
        setAlignType(ALIGN_NONE);
    }
}
