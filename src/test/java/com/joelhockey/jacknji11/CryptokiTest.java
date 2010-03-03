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
    private static final byte[] SO_PIN = "sopin".getBytes();
    private static final byte[] USER_PIN = "userpin".getBytes();
    private static final int TESTSLOT = 0;
    private static final int INITSLOT = 1;
    
    public void setUp() {
        CE.Initialize();
    }
    
    public void tearDown() {
        CE.Finalize();
    }
    
    public void testGetInfo() {
        CK_INFO info = new CK_INFO();
        CE.GetInfo(info);
//        System.out.println(info);
    }

    public void testGetSlotList() {
        int[] slots = CE.GetSlotList(true);
//        System.out.println("num slots: " + slots.length);
    }
    
    public void testGetSlotInfo() {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        CE.GetSlotInfo(TESTSLOT, info);
//        System.out.println(info);
    }

    public void testGetTokenInfo() {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        CE.GetTokenInfo(TESTSLOT, info);
//        System.out.println(info);
    }

    public void testGetMechanismList() {
        for (int mech : CE.GetMechanismList(TESTSLOT)) {
//            System.out.println(String.format("0x%08x : %s", mech, CKM.I2S.get(mech)));
        }
    }
    
    public void testGetMechanismInfo() {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        CE.GetMechanismInfo(TESTSLOT, CKM.AES_CBC, info);
//        System.out.println(info);
    }
    
    public void testInitTokenInitPinSetPin() {
        CE.InitToken(INITSLOT, SO_PIN, "TEST".getBytes());
        int session = CE.OpenSession(1, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.SO, SO_PIN);
        CE.InitPIN(session, USER_PIN);
        CE.Logout(session);
        CE.Login(session, CKU.USER, USER_PIN);
        byte[] somenewpin = "somenewpin".getBytes();
        CE.SetPIN(session, USER_PIN, somenewpin);
        CE.SetPIN(session, somenewpin, USER_PIN);
    }
    
    public void testGetSessionInfo() {
        int session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CE.GetSessionInfo(session, sessionInfo);
        System.out.println(sessionInfo);
    }
    
    public void testCreateCopyDestroyObject() {
        int session = CE.OpenSession(TESTSLOT, CKS.RW_PUBLIC_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CK_ATTRIBUTE[] templ = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.VALUE, "datavalue"),
        };
        int o1 = CE.CreateObject(session, templ);
        int o2 = CE.CopyObject(session, o1, null);
        CE.DestroyObject(session, o1);
        CE.DestroyObject(session, o2);
    }
}
