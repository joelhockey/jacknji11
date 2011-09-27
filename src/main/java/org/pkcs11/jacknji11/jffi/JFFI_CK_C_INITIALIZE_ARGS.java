/*
 * Copyright 2010-2011 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.pkcs11.jacknji11.jffi;

import jnr.ffi.Struct;
import jnr.ffi.annotations.Delegate;
import jnr.ffi.byref.PointerByReference;

import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS.CK_CREATEMUTEX;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS.CK_DESTROYMUTEX;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS.CK_LOCKMUTEX;
import org.pkcs11.jacknji11.CK_C_INITIALIZE_ARGS.CK_UNLOCKMUTEX;
import org.pkcs11.jacknji11.NativePointer;
import org.pkcs11.jacknji11.NativePointerByReference;

/**
 * JFFI wrapper for PKCS#11 CK_C_INITIALIZE_ARGS struct. Also includes JFFI mutex interface wrappers.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_C_INITIALIZE_ARGS extends Struct {

    public JFFI_CK_CREATEMUTEX createMutex;
    public JFFI_CK_DESTROYMUTEX destroyMutex;
    public JFFI_CK_LOCKMUTEX lockMutex;
    public JFFI_CK_UNLOCKMUTEX unlockMutex;
    public long flags;
    public jnr.ffi.Pointer pReserved;

    public JFFI_CK_C_INITIALIZE_ARGS(final CK_C_INITIALIZE_ARGS args) {
        super(jnr.ffi.Runtime.getSystemRuntime());
        this.createMutex = new JFFI_CK_CREATEMUTEX() {
            public long invoke(NativePointerByReference mutex) {
                return args.createMutex.invoke(mutex);
            }
            public long invoke(PointerByReference mutex) {
                return invoke(new NativePointerByReference(
                    new NativePointer(mutex.getValue().address())));
            }
        };
        this.destroyMutex = new JFFI_CK_DESTROYMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.destroyMutex.invoke(mutex);
            }
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.lockMutex = new JFFI_CK_LOCKMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.lockMutex.invoke(mutex);
            }
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.unlockMutex = new JFFI_CK_UNLOCKMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.unlockMutex.invoke(mutex);
            }
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.flags = args.flags;
    }

    /**
     * JNA wrapper for PKCS#11 CK_CREATEMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_CREATEMUTEX extends CK_CREATEMUTEX {
        /**
         * Create Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(PointerByReference mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_DESTROYMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_DESTROYMUTEX extends CK_DESTROYMUTEX {
        /**
         * Destroy Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_LOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_LOCKMUTEX extends CK_LOCKMUTEX {
        /**
         * Lock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_UNLOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_UNLOCKMUTEX extends CK_UNLOCKMUTEX {
        /**
         * Unlock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }
}
