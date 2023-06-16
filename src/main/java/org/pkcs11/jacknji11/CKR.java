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

import java.util.Map;

/**
 * CKR_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKR {
    public static final long OK                          = 0x00000000;
    public static final long CANCEL                      = 0x00000001;
    public static final long HOST_MEMORY                 = 0x00000002;
    public static final long SLOT_ID_INVALID             = 0x00000003;
    public static final long FLAGS_INVALID               = 0x00000004;
    public static final long GENERAL_ERROR               = 0x00000005;
    public static final long FUNCTION_FAILED             = 0x00000006;
    public static final long ARGUMENTS_BAD               = 0x00000007;
    public static final long NO_EVENT                    = 0x00000008;
    public static final long NEED_TO_CREATE_THREADS      = 0x00000009;
    public static final long CANT_LOCK                   = 0x0000000a;
    public static final long ATTRIBUTE_READ_ONLY         = 0x00000010;
    public static final long ATTRIBUTE_SENSITIVE         = 0x00000011;
    public static final long ATTRIBUTE_TYPE_INVALID      = 0x00000012;
    public static final long ATTRIBUTE_VALUE_INVALID     = 0x00000013;
    public static final long DATA_INVALID                = 0x00000020;
    public static final long DATA_LEN_RANGE              = 0x00000021;
    public static final long DEVICE_ERROR                = 0x00000030;
    public static final long DEVICE_MEMORY               = 0x00000031;
    public static final long DEVICE_REMOVED              = 0x00000032;
    public static final long ENCRYPTED_DATA_INVALID      = 0x00000040;
    public static final long ENCRYPTED_DATA_LEN_RANGE    = 0x00000041;
    public static final long FUNCTION_CANCELED           = 0x00000050;
    public static final long FUNCTION_NOT_PARALLEL       = 0x00000051;
    public static final long FUNCTION_PARALLEL           = 0x00000052;
    public static final long FUNCTION_NOT_SUPPORTED      = 0x00000054;
    public static final long KEY_HANDLE_INVALID          = 0x00000060;
    public static final long KEY_SENSITIVE               = 0x00000061;
    public static final long KEY_SIZE_RANGE              = 0x00000062;
    public static final long KEY_TYPE_INCONSISTENT       = 0x00000063;
    public static final long KEY_NOT_NEEDED              = 0x00000064;
    public static final long KEY_CHANGED                 = 0x00000065;
    public static final long KEY_NEEDED                  = 0x00000066;
    public static final long KEY_INDIGESTIBLE            = 0x00000067;
    public static final long KEY_FUNCTION_NOT_PERMITTED  = 0x00000068;
    public static final long KEY_NOT_WRAPPABLE           = 0x00000069;
    public static final long KEY_UNEXTRACTABLE           = 0x0000006a;
    public static final long KEY_PARAMS_INVALID          = 0x0000006b;
    public static final long MECHANISM_INVALID           = 0x00000070;
    public static final long MECHANISM_PARAM_INVALID     = 0x00000071;
    public static final long OBJECT_CLASS_INCONSISTENT   = 0x00000080;
    public static final long OBJECT_CLASS_INVALID        = 0x00000081;
    public static final long OBJECT_HANDLE_INVALID       = 0x00000082;
    public static final long OPERATION_ACTIVE            = 0x00000090;
    public static final long OPERATION_NOT_INITIALIZED   = 0x00000091;
    public static final long PIN_INCORRECT               = 0x000000a0;
    public static final long PIN_INVALID                 = 0x000000a1;
    public static final long PIN_LEN_RANGE               = 0x000000a2;
    public static final long PIN_EXPIRED                 = 0x000000a3;
    public static final long PIN_LOCKED                  = 0x000000a4;
    public static final long SESSION_CLOSED              = 0x000000b0;
    public static final long SESSION_COUNT               = 0x000000b1;
    public static final long SESSION_EXCLUSIVE_EXISTS    = 0x000000b2;
    public static final long SESSION_HANDLE_INVALID      = 0x000000b3;
    public static final long SESSION_PARALLEL_NOT_SUPPORTED = 0x000000b4;
    public static final long SESSION_READ_ONLY           = 0x000000b5;
    public static final long SESSION_EXISTS              = 0x000000b6;
    public static final long SESSION_READ_ONLY_EXISTS    = 0x000000b7;
    public static final long SESSION_READ_WRITE_SO_EXISTS = 0x000000b8;
    public static final long SIGNATURE_INVALID           = 0x000000c0;
    public static final long SIGNATURE_LEN_RANGE         = 0x000000c1;
    public static final long TEMPLATE_INCOMPLETE         = 0x000000d0;
    public static final long TEMPLATE_INCONSISTENT       = 0x000000d1;
    public static final long TOKEN_NOT_PRESENT           = 0x000000e0;
    public static final long TOKEN_NOT_RECOGNIZED        = 0x000000e1;
    public static final long TOKEN_WRITE_PROTECTED       = 0x000000e2;
    public static final long UNWRAPPING_KEY_HANDLE_INVALID = 0x000000f0;
    public static final long UNWRAPPING_KEY_SIZE_RANGE   = 0x000000f1;
    public static final long UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000f2;
    public static final long USER_ALREADY_LOGGED_IN      = 0x00000100;
    public static final long USER_NOT_LOGGED_IN          = 0x00000101;
    public static final long USER_PIN_NOT_INITIALIZED    = 0x00000102;
    public static final long USER_TYPE_INVALID           = 0x00000103;
    public static final long USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104;
    public static final long USER_TOO_MANY_TYPES         = 0x00000105;
    public static final long WRAPPED_KEY_INVALID         = 0x00000110;
    public static final long WRAPPED_KEY_LEN_RANGE       = 0x00000112;
    public static final long WRAPPING_KEY_HANDLE_INVALID = 0x00000113;
    public static final long WRAPPING_KEY_SIZE_RANGE     = 0x00000114;
    public static final long WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115;
    public static final long RANDOM_SEED_NOT_SUPPORTED   = 0x00000120;
    public static final long RANDOM_NO_RNG               = 0x00000121;
    public static final long DOMAIN_PARAMS_INVALID       = 0x00000130;
    public static final long CKR_CURVE_NOT_SUPPORTED     = 0x00000140;
    public static final long BUFFER_TOO_SMALL            = 0x00000150;
    public static final long SAVED_STATE_INVALID         = 0x00000160;
    public static final long INFORMATION_SENSITIVE       = 0x00000170;
    public static final long STATE_UNSAVEABLE            = 0x00000180;
    public static final long CRYPTOKI_NOT_INITIALIZED    = 0x00000190;
    public static final long CRYPTOKI_ALREADY_INITIALIZED = 0x00000191;
    public static final long MUTEX_BAD                   = 0x000001a0;
    public static final long MUTEX_NOT_LOCKED            = 0x000001a1;
    public static final long FUNCTION_REJECTED           = 0x00000200;
    public static final long VENDOR_DEFINED              = 0x80000000;

    // Vendor defined values
    // Eracom PTK
    public static final long VENDOR_PTK_ERACOM_ERROR     = 0x80000100;
    public static final long VENDOR_PTK_TIME_STAMP       = 0x80000101;
    public static final long VENDOR_PTK_ACCESS_DENIED    = 0x80000102;
    public static final long VENDOR_PTK_CRYPTOKI_UNUSABLE = 0x80000103;
    public static final long VENDOR_PTK_ENCODE_ERROR     = 0x80000104;
    public static final long VENDOR_PTK_V_CONFIG         = 0x80000105;
    public static final long VENDOR_PTK_SO_NOT_LOGGED_IN = 0x80000106;
    public static final long VENDOR_PTK_CERT_NOT_VALIDATED = 0x80000107;
    public static final long VENDOR_PTK_PIN_ALREADY_INITIALIZED = 0x80000108;
    public static final long VENDOR_PTK_REMOTE_SERVER_ERROR = 0x8000010a;
    public static final long VENDOR_PTK_CSA_HW_ERROR     = 0x8000010b;
    public static final long VENDOR_PTK_NO_CHALLENGE     = 0x80000110;
    public static final long VENDOR_PTK_RESPONSE_INVALID = 0x80000111;
    public static final long VENDOR_PTK_EVENT_LOG_NOT_FULL = 0x80000113;
    public static final long VENDOR_PTK_OBJECT_READ_ONLY = 0x80000114;
    public static final long VENDOR_PTK_TOKEN_READ_ONLY  = 0x80000115;
    public static final long VENDOR_PTK_TOKEN_NOT_INITIALIZED = 0x80000116;
    public static final long VENDOR_PTK_NOT_ADMIN_TOKEN  = 0x80000117;
    public static final long VENDOR_PTK_AUTHENTICATION_REQUIRED = 0x80000130;
    public static final long VENDOR_PTK_OPERATION_NOT_PERMITTED = 0x80000131;
    public static final long VENDOR_PTK_PKCS12_DECODE    = 0x80000132;
    public static final long VENDOR_PTK_PKCS12_UNSUPPORTED_SAFEBAG_TYPE = 0x80000133;
    public static final long VENDOR_PTK_PKCS12_UNSUPPORTED_PRIVACY_MODE = 0x80000134;
    public static final long VENDOR_PTK_PKCS12_UNSUPPORTED_INTEGRITY_MODE = 0x80000135;
    public static final long VENDOR_PTK_VALUE_NOT_ODD_PARITY = 0x80000140;

    public static final long VENDOR_PTK_MSG_ERROR = 0x80000300;
    public static final long VENDOR_PTK_NEED_IV_UPDATE = 0x80000310;
    public static final long VENDOR_PTK_DUPLICATE_IV_FOUND = 0x80000311;
    public static final long VENDOR_PTK_CANNOT_DERIVE_KEYS = 0x80000381;
    public static final long VENDOR_PTK_BAD_REQ_SIGNATURE= 0x80000382;
    public static final long VENDOR_PTK_BAD_REPLY_SIGNATURE = 0x80000383;
    public static final long VENDOR_PTK_SMS_ERROR        = 0x80000384;
    public static final long VENDOR_PTK_BAD_PROTECTION   = 0x80000385;
    public static final long VENDOR_PTK_DEVICE_RESET     = 0x80000386;
    public static final long VENDOR_PTK_NO_SESSION_KEYS  = 0x80000387;
    public static final long VENDOR_PTK_BAD_REPLY        = 0x80000388;
    public static final long VENDOR_PTK_KEY_ROLLOVER     = 0x80000389;

    public static final long VENDOR_PTK_HOST_ERROR       = 0x80001000;
    public static final long VENDOR_PTK_BAD_REQUEST      = 0x80001001;
    public static final long VENDOR_PTK_BAD_ATTRIBUTE_PACKING = 0x80001002;
    public static final long VENDOR_PTK_BAD_ATTRIBUTE_COUNT = 0x80001003;
    public static final long VENDOR_PTK_BAD_PARAM_PACKING= 0x80001004;
    public static final long VENDOR_PTK_EXTERN_DCP_ERROR = 0x80001386;
    public static final long VENDOR_PTK_HIMK_NOT_FOUND   = 0x80001400;

    public static final long VENDOR_PTK_WLD_ERROR        = 0x80002000;
    public static final long VENDOR_PTK_WLD_CONFIG_NOT_FOUND = 0x80002001;
    public static final long VENDOR_PTK_WLD_CONFIG_ITEM_READ_FAILED = 0x80002002;
    public static final long VENDOR_PTK_WLD_CONFIG_NO_TOKEN_LABEL = 0x80002003;
    public static final long VENDOR_PTK_WLD_CONFIG_TOKEN_LABEL_LEN = 0x80002004;
    public static final long VENDOR_PTK_WLD_CONFIG_TOKEN_SERIAL_NUM_LEN = 0x80002005;
    public static final long VENDOR_PTK_WLD_CONFIG_SLOT_DESCRIPTION_LEN = 0x80002006;
    public static final long VENDOR_PTK_WLD_CONFIG_ITEM_FORMAT_INVALID = 0x80002007;
    public static final long VENDOR_PTK_WLD_LOGIN_CACHE_INCONSISTENT = 0x80002010;

    // Thales Luna, from cryptoki_v2.h
    public static final long VENDOR_LUNA_RC_ERROR = 0x80000004;
    public static final long VENDOR_LUNA_CONTAINER_HANDLE_INVALID = 0x80000005;
    public static final long VENDOR_LUNA_TOO_MANY_CONTAINERS = 0x80000006;
    public static final long VENDOR_LUNA_USER_LOCKED_OUT = 0x80000007;
    public static final long VENDOR_LUNA_CLONING_PARAMETER_ALREADY_EXISTS = 0x80000008;
    public static final long VENDOR_LUNA_CLONING_PARAMETER_MISSING = 0x80000009;
    public static final long VENDOR_LUNA_CERTIFICATE_DATA_MISSING = 0x8000000a;
    public static final long VENDOR_LUNA_CERTIFICATE_DATA_INVALID = 0x8000000b;
    public static final long VENDOR_LUNA_ACCEL_DEVICE_ERROR = 0x8000000c;
    public static final long VENDOR_LUNA_WRAPPING_ERROR = 0x8000000d;
    public static final long VENDOR_LUNA_UNWRAPPING_ERROR = 0x8000000e;
    public static final long VENDOR_LUNA_MAC_MISSING = 0x8000000f;
    public static final long VENDOR_LUNA_DAC_POLICY_PID_MISMATCH = 0x80000010;
    public static final long VENDOR_LUNA_DAC_MISSING = 0x80000011;
    public static final long VENDOR_LUNA_BAD_DAC = 0x80000012;
    public static final long VENDOR_LUNA_SSK_MISSING = 0x80000013;
    public static final long VENDOR_LUNA_BAD_MAC = 0x80000014;
    public static final long VENDOR_LUNA_DAK_MISSING = 0x80000015;
    public static final long VENDOR_LUNA_BAD_DAK = 0x80000016;
    public static final long VENDOR_LUNA_SIM_AUTHORIZATION_FAILED = 0x80000017;
    public static final long VENDOR_LUNA_SIM_VERSION_UNSUPPORTED = 0x80000018;
    public static final long VENDOR_LUNA_SIM_CORRUPT_DATA = 0x80000019;
    public static final long VENDOR_LUNA_USER_NOT_AUTHORIZED = 0x8000001a;
    public static final long VENDOR_LUNA_MAX_OBJECT_COUNT_EXCEEDED = 0x8000001b;
    public static final long VENDOR_LUNA_SO_LOGIN_FAILURE_THRESHOLD = 0x8000001c;
    public static final long VENDOR_LUNA_SIM_AUTHFORM_INVALID = 0x8000001d;
    public static final long VENDOR_LUNA_CITS_DAK_MISSING = 0x8000001e;
    public static final long VENDOR_LUNA_UNABLE_TO_CONNECT = 0x8000001f;
    public static final long VENDOR_LUNA_PARTITION_DISABLED = 0x80000020;
    public static final long VENDOR_LUNA_CALLBACK_ERROR = 0x80000021;
    public static final long VENDOR_LUNA_SECURITY_PARAMETER_MISSING = 0x80000022;
    public static final long VENDOR_LUNA_SP_TIMEOUT = 0x80000023;
    public static final long VENDOR_LUNA_TIMEOUT = 0x80000024;
    public static final long VENDOR_LUNA_ECC_UNKNOWN_CURVE = 0x80000025;
    public static final long VENDOR_LUNA_MTK_ZEROIZED = 0x80000026;
    public static final long VENDOR_LUNA_MTK_STATE_INVALID = 0x80000027;
    public static final long VENDOR_LUNA_INVALID_ENTRY_TYPE = 0x80000028;
    public static final long VENDOR_LUNA_MTK_SPLIT_INVALID = 0x80000029;
    public static final long VENDOR_LUNA_HSM_STORAGE_FULL = 0x8000002a;
    public static final long VENDOR_LUNA_DEVICE_TIMEOUT = 0x8000002b;
    public static final long VENDOR_LUNA_CONTAINER_OBJECT_STORAGE_FULL = 0x8000002c;
    public static final long VENDOR_LUNA_PED_CLIENT_NOT_RUNNING = 0x8000002d;
    public static final long VENDOR_LUNA_PED_UNPLUGGED = 0x8000002e;
    public static final long VENDOR_LUNA_ECC_POINT_INVALID = 0x8000002f;
    public static final long VENDOR_LUNA_OPERATION_NOT_ALLOWED = 0x80000030;
    public static final long VENDOR_LUNA_LICENSE_CAPACITY_EXCEEDED = 0x80000031;
    public static final long VENDOR_LUNA_LOG_FILE_NOT_OPEN = 0x80000032;
    public static final long VENDOR_LUNA_LOG_FILE_WRITE_ERROR = 0x80000033;
    public static final long VENDOR_LUNA_LOG_BAD_FILE_NAME = 0x80000034;
    public static final long VENDOR_LUNA_LOG_FULL = 0x80000035;
    public static final long VENDOR_LUNA_LOG_NO_KCV = 0x80000036;
    public static final long VENDOR_LUNA_LOG_BAD_RECORD_HMAC = 0x80000037;
    public static final long VENDOR_LUNA_LOG_BAD_TIME = 0x80000038;
    public static final long VENDOR_LUNA_LOG_AUDIT_NOT_INITIALIZED = 0x80000039;
    public static final long VENDOR_LUNA_LOG_RESYNC_NEEDED = 0x8000003a;
    public static final long VENDOR_LUNA_AUDIT_LOGIN_TIMEOUT_IN_PROGRESS = 0x8000003b;
    public static final long VENDOR_LUNA_AUDIT_LOGIN_FAILURE_THRESHOLD = 0x8000003c;
    public static final long VENDOR_LUNA_INVALID_FUF_TARGET = 0x8000003d;
    public static final long VENDOR_LUNA_INVALID_FUF_HEADER = 0x8000003e;
    public static final long VENDOR_LUNA_INVALID_FUF_VERSION = 0x8000003f;
    public static final long VENDOR_LUNA_ECC_ECC_RESULT_AT_INF = 0x80000040;
    public static final long VENDOR_LUNA_AGAIN = 0x80000041;
    public static final long VENDOR_LUNA_TOKEN_COPIED = 0x80000042;
    public static final long VENDOR_LUNA_SLOT_NOT_EMPTY = 0x80000043;
    public static final long VENDOR_LUNA_USER_ALREADY_ACTIVATED = 0x80000044;
    public static final long VENDOR_LUNA_FM_ID_INVALID = 0x80000088;
    public static final long VENDOR_LUNA_FM_NOT_SUPPORTED = 0x80000089;
    public static final long VENDOR_LUNA_FM_NEVER_ENABLED = 0x8000008a;
    public static final long VENDOR_LUNA_FM_DISABLED = 0x8000008b;
    public static final long VENDOR_LUNA_FM_SMFS_INACTIVE = 0x8000008c;
    public static final long VENDOR_LUNA_HSM_RESTART_REQUIRED = 0x8000008d;
    public static final long VENDOR_LUNA_FM_CFG_ALLOWEDFLAG_DISABLED = 0x8000008e;
    public static final long VENDOR_LUNA_ASSIGNED_KEY_REQUIRES_AUTH_DATA = 0x8000008f;
    public static final long VENDOR_LUNA_ROLE_CANNOT_MAKE_KEYS_ASSIGNED = 0x80000090;
    public static final long VENDOR_LUNA_ASSIGNED_KEY_CANNOT_BE_MODIFIED = 0x80000091;
    public static final long VENDOR_LUNA_AUTH_DATA_TOO_LARGE = 0x80000092;
    public static final long VENDOR_LUNA_AUTH_DATA_TOO_SMALL = 0x80000093;
    public static final long VENDOR_LUNA_OH_AUTH_DATA_NOT_PROVIDED = 0x80000094;
    public static final long VENDOR_LUNA_ASSIGNED_KEY_FAILED_ATTRIBUTE_DEPENDENCIES = 0x80000095;
    public static final long VENDOR_LUNA_KEY_CANNOT_BE_AUTHORIZED = 0x80000096;
    public static final long VENDOR_LUNA_KEY_NOT_AUTHORIZED = 0x80000097;
    public static final long VENDOR_LUNA_AUTH_DATA_INCORRECT = 0x80000098;
    public static final long VENDOR_LUNA_SMK_ID_NOT_FOUND = 0x80000099;
    public static final long VENDOR_LUNA_INTERNAL_INTEGRITY_ERROR = 0x8000009a;
    public static final long VENDOR_LUNA_ASSIGNED_KEY_CANNOT_BE_RESET = 0x8000009b;
    public static final long VENDOR_LUNA_AUTH_DATA_INCORRECT_AND_LIMIT_REACHED = 0x8000009c;
    public static final long VENDOR_LUNA_PED_UNSUPPORTED = 0x8000009d;
    public static final long VENDOR_LUNA_PED_ERROR = 0x8000009e;
    public static final long VENDOR_LUNA_ACCESS_ID_CONFLICT = 0x8000009f;
    public static final long VENDOR_LUNA_KEY_INVALID_FOR_HA_LOGIN = 0x80000100;
    public static final long VENDOR_LUNA_KEY_EXTRACTABLE = 0x80000101;
    public static final long VENDOR_LUNA_AUTH_DATA_NOT_ALLOWED = 0x80000102;
    public static final long VENDOR_LUNA_ASSIGNED_KEY_NOT_ALLOWED = 0x80000103;
    public static final long VENDOR_LUNA_INTEGER_OVERFLOW = 0x80000104;
    public static final long VENDOR_LUNA_ECC_CURVE_NOT_ALLOWED = 0x80000105;
    public static final long VENDOR_LUNA_XTC_ERROR = 0x80001600;
    public static final long VENDOR_LUNA_CONTEXT_INVALID = 0x80001601;
    public static final long VENDOR_LUNA_MAX_SESSION_OBJECT_COUNT = 0x80001602;
    public static final long VENDOR_LUNA_MAX_SESSION_COUNT = 0x80001604;
    public static final long VENDOR_LUNA_BUSY = 0x80001604;
    public static final long VENDOR_LUNA_NETWORK_ERROR = 0x80001605;
    public static final long VENDOR_LUNA_SERVICE_UNAVAILABLE = 0x80001606;
    
    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKR.class);
    /**
     * Convert long constant value to name.
     * @param ckr value
     * @return name
     */
    public static final String L2S(long ckr) { return C.l2s(L2S, CKR.class.getSimpleName(), ckr); }
}
