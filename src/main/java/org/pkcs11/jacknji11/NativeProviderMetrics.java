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
package org.pkcs11.jacknji11;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static java.util.Collections.synchronizedMap;

/**
 * Metrics class keeps track of the number of attempts, duration and exceptions for each method in the {@link NativeProvider}.
 * <p>
 * To intercept the {@link NativeProvider}, the Metrics class uses a {@link Proxy} mechanism.
 * <p>
 * The keys of the metrics are the name of the methods from PKCS#11 spec (e.g. C_Initialize, C_Finalize, etc.). Use
 * the constants from this class to access the metrics by method name.
 * <p>
 * The measurements are done using System.currentTimeMillis() and therefore are limited to the precision of the system clock.
 *
 * @author Tomasz Wysocki
 */
public class NativeProviderMetrics {

    public static final String C_Initialize = "C_Initialize";
    public static final String C_Finalize = "C_Finalize";
    public static final String C_GetInfo = "C_GetInfo";
    public static final String C_GetSlotList = "C_GetSlotList";
    public static final String C_GetSlotInfo = "C_GetSlotInfo";
    public static final String C_GetTokenInfo = "C_GetTokenInfo";
    public static final String C_WaitForSlotEvent = "C_WaitForSlotEvent";
    public static final String C_GetMechanismList = "C_GetMechanismList";
    public static final String C_GetMechanismInfo = "C_GetMechanismInfo";
    public static final String C_InitToken = "C_InitToken";
    public static final String C_InitPIN = "C_InitPIN";
    public static final String C_SetPIN = "C_SetPIN";
    public static final String C_OpenSession = "C_OpenSession";
    public static final String C_CloseSession = "C_CloseSession";
    public static final String C_CloseAllSessions = "C_CloseAllSessions";
    public static final String C_GetSessionInfo = "C_GetSessionInfo";
    public static final String C_GetOperationState = "C_GetOperationState";
    public static final String C_SetOperationState = "C_SetOperationState";
    public static final String C_Login = "C_Login";
    public static final String C_Logout = "C_Logout";
    public static final String C_CreateObject = "C_CreateObject";
    public static final String C_CopyObject = "C_CopyObject";
    public static final String C_DestroyObject = "C_DestroyObject";
    public static final String C_GetObjectSize = "C_GetObjectSize";
    public static final String C_GetAttributeValue = "C_GetAttributeValue";
    public static final String C_SetAttributeValue = "C_SetAttributeValue";
    public static final String C_FindObjectsInit = "C_FindObjectsInit";
    public static final String C_FindObjects = "C_FindObjects";
    public static final String C_FindObjectsFinal = "C_FindObjectsFinal";
    public static final String C_EncryptInit = "C_EncryptInit";
    public static final String C_Encrypt = "C_Encrypt";
    public static final String C_EncryptUpdate = "C_EncryptUpdate";
    public static final String C_EncryptFinal = "C_EncryptFinal";
    public static final String C_DecryptInit = "C_DecryptInit";
    public static final String C_Decrypt = "C_Decrypt";
    public static final String C_DecryptUpdate = "C_DecryptUpdate";
    public static final String C_DecryptFinal = "C_DecryptFinal";
    public static final String C_DigestInit = "C_DigestInit";
    public static final String C_Digest = "C_Digest";
    public static final String C_DigestUpdate = "C_DigestUpdate";
    public static final String C_DigestKey = "C_DigestKey";
    public static final String C_DigestFinal = "C_DigestFinal";
    public static final String C_SignInit = "C_SignInit";
    public static final String C_Sign = "C_Sign";
    public static final String C_SignUpdate = "C_SignUpdate";
    public static final String C_SignFinal = "C_SignFinal";
    public static final String C_SignRecoverInit = "C_SignRecoverInit";
    public static final String C_SignRecover = "C_SignRecover";
    public static final String C_VerifyInit = "C_VerifyInit";
    public static final String C_Verify = "C_Verify";
    public static final String C_VerifyUpdate = "C_VerifyUpdate";
    public static final String C_VerifyFinal = "C_VerifyFinal";
    public static final String C_VerifyRecoverInit = "C_VerifyRecoverInit";
    public static final String C_VerifyRecover = "C_VerifyRecover";
    public static final String C_DigestEncryptUpdate = "C_DigestEncryptUpdate";
    public static final String C_DecryptDigestUpdate = "C_DecryptDigestUpdate";
    public static final String C_SignEncryptUpdate = "C_SignEncryptUpdate";
    public static final String C_DecryptVerifyUpdate = "C_DecryptVerifyUpdate";
    public static final String C_GenerateKey = "C_GenerateKey";
    public static final String C_GenerateKeyPair = "C_GenerateKeyPair";
    public static final String C_WrapKey = "C_WrapKey";
    public static final String C_UnwrapKey = "C_UnwrapKey";
    public static final String C_DeriveKey = "C_DeriveKey";
    public static final String C_SeedRandom = "C_SeedRandom";
    public static final String C_GenerateRandom = "C_GenerateRandom";
    public static final String C_GetFunctionStatus = "C_GetFunctionStatus";
    public static final String C_CancelFunction = "C_CancelFunction";

    /**
     * List of all metric entries per method.
     */
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /**
     * Entry for a method in the {@link NativeProvider}.
     * <p>
     * It keeps track of the number of attempts, duration and exceptions for the method.
     */
    private static class Entry {

        // number of attempts the method was called (registered before the method is called)
        AtomicInteger attempts;

        // total duration of all attempts, only successful attempts are counted (those that have not thrown an exception)
        AtomicLong duration;

        // number of attempts per result (return value)
        Map<Long, AtomicInteger> attemptsPerResult;

        // total duration of all attempts per result (return value)
        Map<Long, AtomicLong> durationPerResult;

        // number of exceptions per exception class
        Map<Class<?>, AtomicInteger> exceptions;

        Entry() {
            attempts = new AtomicInteger(0);
            duration = new AtomicLong(0);
            attemptsPerResult = synchronizedMap(new HashMap<>());
            durationPerResult = synchronizedMap(new HashMap<>());
            exceptions = synchronizedMap(new HashMap<>());
        }

        private void incDuration(long rv, long ms) {
            duration(rv).addAndGet(ms);
        }

        private AtomicLong duration(long rv) {
            return durationPerResult.computeIfAbsent(rv, k -> new AtomicLong(0));
        }

        private void incAttempts(long rv) {
            attempts(rv).incrementAndGet();
        }

        private AtomicInteger attempts(long rv) {
            return attemptsPerResult.computeIfAbsent(rv, k -> new AtomicInteger(0));
        }

        void incError(Class<?> exceptionClass) {
            exceptionCounter(exceptionClass).incrementAndGet();
        }

        private AtomicInteger exceptionCounter(Class<?> exceptionClass) {
            return exceptions.computeIfAbsent(exceptionClass, k -> new AtomicInteger(0));
        }

        int getAttempts() {
            return attempts.get();
        }

        long getDuration() {
            return duration.get();
        }

        int getAttempts(long rv) {
            return attempts(rv).get();
        }

        int getExceptions(Class<?> exceptionClass) {
            return exceptionCounter(exceptionClass).get();
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("  Attempts: ").append(attempts.get()).append("\n");

            sb.append("  Duration: ").append(formatDuration(duration.get(), attempts.get())).append("\n");
            for (Map.Entry<Long, AtomicInteger> entry : attemptsPerResult.entrySet()) {
                int attempts = entry.getValue().intValue();
                long duration = duration(entry.getKey()).get();
                sb.append("  ");
                sb.append(CKR.L2S(entry.getKey()));
                sb.append(" -> ");
                sb.append(attempts);
                sb.append(" (");
                sb.append(formatDuration(duration, attempts));
                sb.append(")");
                sb.append("\n");
            }
            for (Map.Entry<Class<?>, AtomicInteger> entry : exceptions.entrySet()) {
                sb.append("Exception: ").append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
            }
            return sb.toString();
        }

        private String formatDuration(long duration, long attempts) {
            return String.format("total: %dms avg: %4.2fms", duration, duration * 1.0 / attempts);
        }

        void result(long rv, long ms) {
            this.duration.addAndGet(ms);
            incAttempts(rv);
            incDuration(rv, ms);
        }

        void incAttempts() {
            attempts.incrementAndGet();
        }
    }

    /**
     * Reset all metrics.
     */
    public void reset() {
        entries.clear();
    }

    /**
     * Register a result for a method (after the method is called).
     * @param method the name of the method
     * @param rv the return value
     * @param ms the duration of the method call in milliseconds
     */
    void registerResult(String method, long rv, long ms) {
        getEntry(method).result(rv, ms);
    }

    /**
     * Register an attempt for a method (before the method is called).
     *
     * @param method the name of the method
     */
    void registerAttempt(String method) {
        getEntry(method).incAttempts();
    }

    /**
     * Get or create an entry for a method.
     *
     * @param name the name of the method
     * @return the entry for the method
     */
    private Entry getEntry(String name) {
        return entries.computeIfAbsent(name, k -> new Entry());
    }

    /**
     * Get the number of attempts for a method.
     *
     * @param method the name of the method
     * @return the number of attempts
     */
    public int getAttempts(String method) {
        return getEntry(method).getAttempts();
    }

    /**
     * Get the number of attempts for a method and a specific return value.
     *
     * @param method the name of the method
     * @param rv the return value
     * @return the number of attempts
     */
    public int getAttempts(String method, long rv) {
        return getEntry(method).getAttempts(rv);
    }

    /**
     * Get total duration of all attempts for a method.
     *
     * @param method the name of the method
     * @return the total duration of all attempts
     */
    public long getDuration(String method) {
        return getEntry(method).getDuration();
    }

    /**
     * Get total duration of all attempts for a method and a specific return value.
     *
     * @param method the name of the method
     * @param rv the return value
     * @return the total duration of all attempts for a method and a specific return value
     */
    public long getDuration(String method, long rv) {
        return getEntry(method).duration(rv).get();
    }

    /**
     * Get the number of exceptions for a method and a specific exception class.
     *
     * @param key the name of the method
     * @param exceptionClass the exception class
     * @return the number of exceptions
     */
    public int getExceptions(String key, Class<?> exceptionClass) {
        return getEntry(key).getExceptions(exceptionClass);
    }

    /**
     * Intercept given instance of NativeProvider by creating a proxy
     * that will call the original methods and measure counts, duration and exceptions.
     *
     * @param nativeProvider the instance of NativeProvider to intercept
     * @return the intercepted instance of NativeProvider (proxy)
     */
    NativeProvider intercept(NativeProvider nativeProvider) {
        return (NativeProvider) Proxy.newProxyInstance(
                nativeProvider.getClass().getClassLoader(),
                new Class[]{NativeProvider.class},
                (proxy, method, args) -> handleMethod(nativeProvider, method, args)
        );
    }

    /**
     * Catch all methods from NativeProvider starting with C_ and call {@link #handleCryptokiMethod(NativeProvider, Method, Object[])}.
     *
     * @param nativeProvider the instance of NativeProvider (original)
     * @param method the method to call
     * @param args the arguments for the method
     * @return the result of the method
     */
    private Object handleMethod(NativeProvider nativeProvider, Method method, Object[] args) throws IllegalAccessException, InvocationTargetException {
        // catch only methods from NativeProvider starting with C_
        if (method.getDeclaringClass() == NativeProvider.class) {
            if (method.getName().startsWith("C_")) {
                return handleCryptokiMethod(nativeProvider, method, args);
            }
        }
        return method.invoke(nativeProvider, args);
    }

    /**
     * Handle the method call by calling the original method and measuring counts, duration and exceptions.
     *
     * @param nativeProvider the instance of NativeProvider (original)
     * @param method the method to call
     * @param args the arguments for the method
     * @return the result of the method
     */
    private long handleCryptokiMethod(NativeProvider nativeProvider, Method method, Object[] args) throws IllegalAccessException, InvocationTargetException {
        String name = method.getName();
        try {
            registerAttempt(name);
            long s = System.currentTimeMillis();
            // all C_ methods return long
            long rv = (long) method.invoke(nativeProvider, args);
            long e = System.currentTimeMillis();
            registerResult(name, rv, e-s);
            return rv;
        } catch (RuntimeException exc) {
            incError(name, exc.getClass());
            throw exc;
        }
    }

    /**
     * Increment the number of exceptions for a method and a specific exception class.
     *
     * @param method the name of the method
     * @param exceptionClass the exception class to increment
     */
    private void incError(String method, Class<?> exceptionClass) {
        getEntry(method).incError(exceptionClass);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Entry> entry : entries.entrySet()) {
            sb.append(entry.getKey()).append(":\n");
            sb.append(entry.getValue());
        }
        return sb.toString();
    }
}
