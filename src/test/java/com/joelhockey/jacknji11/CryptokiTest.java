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

import com.joelhockey.jacknji11.CE;
import com.joelhockey.jacknji11.CKM;
import com.joelhockey.jacknji11.CK_INFO;
import com.joelhockey.jacknji11.CK_MECHANISM_INFO;
import com.joelhockey.jacknji11.CK_SLOT_INFO;
import com.joelhockey.jacknji11.CK_TOKEN_INFO;

import junit.framework.TestCase;

public class CryptokiTest extends TestCase {
    public void setUp() {
        CE.Initialize();
    }
    
    public void tearDown() {
        CE.Finalize();
    }
    
    public void testGetInfo() {
        CK_INFO info = new CK_INFO();
        CE.GetInfo(info);
        System.out.println(info);
    }

    public void testGetSlotList() {
        int[] slots = CE.GetSlotList(true);
        System.out.println("num slots: " + slots.length);
    }
    
    public void testGetSlotInfo() {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        CE.GetSlotInfo(0, info);
        System.out.println(info);
    }

    public void testGetTokenInfo() {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        CE.GetTokenInfo(0, info);
        System.out.println(info);
    }

    public void testGetMechanismList() {
        for (int mech : CE.GetMechanismList(0)) {
            System.out.println(String.format("0x%08x : %s", mech, CKM.I2S.get(mech)));
        }
    }
    
    public void testGetMechanismInfo() {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        CE.GetMechanismInfo(0, CKM.AES_CBC, info);
        System.out.println(info);
    }
    
    public void testInitToken() {
        CE.InitToken(3, "ytrewq".getBytes(), "TEST".getBytes());
    }
}
