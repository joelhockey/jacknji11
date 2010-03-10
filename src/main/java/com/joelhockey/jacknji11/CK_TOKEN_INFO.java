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
 * JNA wrapper for PKCS#11 CK_TOKEN_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_TOKEN_INFO extends Structure {
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
