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

import com.sun.jna.Callback;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

/**
 * JNA wrapper for PKCS#11 CK_C_INITIALIZE_ARGS struct. Also includes JNA mutex interface wrappers.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_C_INITIALIZE_ARGS extends Structure {

    /**
     * True if application threads which are executing calls to the library may not use native operating system calls to
     * spawn new threads; false if they may.
     */
    public static final int CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001;
    /** True if the library can use the native operation system threading model for locking; false otherwise. */
    public static final int CKF_OS_LOCKING_OK = 0x00000002;

    public CK_CREATEMUTEX CreateMutex;
    public CK_DESTROYMUTEX DestroyMutex;
    public CK_LOCKMUTEX LockMutex;
    public CK_UNLOCKMUTEX UnlockMutex;
    public NativeLong flags;
    public Pointer pReserved;

    /**
     * Initialise struct with supplied values.
     * @param createMutex create mutex
     * @param destroyMutex destroy mutex
     * @param lockMutex lock mutex
     * @param unlockMutex unlock mutex
     * @param flags locking flags constant from CKF
     */
    public CK_C_INITIALIZE_ARGS(CK_CREATEMUTEX createMutex, CK_DESTROYMUTEX destroyMutex, CK_LOCKMUTEX lockMutex,
            CK_UNLOCKMUTEX unlockMutex, int flags) {

        CreateMutex = createMutex;
        DestroyMutex = destroyMutex;
        LockMutex = lockMutex;
        UnlockMutex = unlockMutex;
        this.flags = new NativeLong(flags);
    }

    /**
     * JNA wrapper for PKCS#11 CK_CREATEMUTEX.
     * @author Joel Hockey
     */
    public interface CK_CREATEMUTEX extends Callback {
        /**
         * Create Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(PointerByReference mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_DESTROYMUTEX.
     * @author Joel Hockey
     */
    public interface CK_DESTROYMUTEX extends Callback {
        /**
         * Destroy Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_LOCKMUTEX.
     * @author Joel Hockey
     */
    public interface CK_LOCKMUTEX extends Callback {
        /**
         * Lock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_UNLOCKMUTEX.
     * @author Joel Hockey
     */
    public interface CK_UNLOCKMUTEX extends Callback {
        /**
         * Unlock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }
}
