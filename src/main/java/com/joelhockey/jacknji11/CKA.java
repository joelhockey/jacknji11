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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * CKA_? constants.
 */
public class CKA {
    public static final int CLASS                       = 0x00000000;
    public static final int TOKEN                       = 0x00000001;
    public static final int PRIVATE                     = 0x00000002;
    public static final int LABEL                       = 0x00000003;
    public static final int APPLICATION                 = 0x00000010;
    public static final int VALUE                       = 0x00000011;
    public static final int OBJECT_ID                   = 0x00000012;
    public static final int CERTIFICATE_TYPE            = 0x00000080;
    public static final int ISSUER                      = 0x00000081;
    public static final int SERIAL_NUMBER               = 0x00000082;
    public static final int AC_ISSUER                   = 0x00000083;
    public static final int OWNER                       = 0x00000084;
    public static final int ATTR_TYPES                  = 0x00000085;
    public static final int TRUSTED                     = 0x00000086;
    public static final int KEY_TYPE                    = 0x00000100;
    public static final int SUBJECT                     = 0x00000101;
    public static final int ID                          = 0x00000102;
    public static final int SENSITIVE                   = 0x00000103;
    public static final int ENCRYPT                     = 0x00000104;
    public static final int DECRYPT                     = 0x00000105;
    public static final int WRAP                        = 0x00000106;
    public static final int UNWRAP                      = 0x00000107;
    public static final int SIGN                        = 0x00000108;
    public static final int SIGN_RECOVER                = 0x00000109;
    public static final int VERIFY                      = 0x0000010a;
    public static final int VERIFY_RECOVER              = 0x0000010b;
    public static final int DERIVE                      = 0x0000010c;
    public static final int START_DATE                  = 0x00000110;
    public static final int END_DATE                    = 0x00000111;
    public static final int MODULUS                     = 0x00000120;
    public static final int MODULUS_BITS                = 0x00000121;
    public static final int PUBLIC_EXPONENT             = 0x00000122;
    public static final int PRIVATE_EXPONENT            = 0x00000123;
    public static final int PRIME_1                     = 0x00000124;
    public static final int PRIME_2                     = 0x00000125;
    public static final int EXPONENT_1                  = 0x00000126;
    public static final int EXPONENT_2                  = 0x00000127;
    public static final int COEFFICIENT                 = 0x00000128;
    public static final int PRIME                       = 0x00000130;
    public static final int SUBPRIME                    = 0x00000131;
    public static final int BASE                        = 0x00000132;
    public static final int PRIME_BITS                  = 0x00000133;
    public static final int SUB_PRIME_BITS              = 0x00000134;
    public static final int VALUE_BITS                  = 0x00000160;
    public static final int VALUE_LEN                   = 0x00000161;
    public static final int EXTRACTABLE                 = 0x00000162;
    public static final int LOCAL                       = 0x00000163;
    public static final int NEVER_EXTRACTABLE           = 0x00000164;
    public static final int ALWAYS_SENSITIVE            = 0x00000165;
    public static final int MODIFIABLE                  = 0x00000170;
    public static final int EC_PARAMS                   = 0x00000180;
    public static final int EC_POINT                    = 0x00000181;
    public static final int SECONDARY_AUTH              = 0x00000200;
    public static final int AUTH_PIN_FLAGS              = 0x00000201;
    public static final int HW_FEATURE_TYPE             = 0x00000300;
    public static final int RESET_ON_INIT               = 0x00000301;
    public static final int HAS_RESET                   = 0x00000302;
    public static final int INVALID_VALUE               = 0xffffffff;

    // Vendor defined values
    // Eracom PTK
    public static final int VENDOR_PTK_USAGE_COUNT      = 0x80000101;
    public static final int VENDOR_PTK_TIME_STAMP       = 0x80000102;
    public static final int VENDOR_PTK_CHECK_VALUE      = 0x80000103;
    public static final int VENDOR_PTK_MECHANISM_LIST   = 0x80000104;
    public static final int VENDOR_PTK_SIGN_LOCAL_CERT  = 0x80000127;
    public static final int VENDOR_PTK_EXPORT           = 0x80000128;
    public static final int VENDOR_PTK_EXPORTABLE       = 0x80000129;
    public static final int VENDOR_PTK_DELETABLE        = 0x8000012a;
    public static final int VENDOR_PTK_IMPORT           = 0x8000012b;
    public static final int VENDOR_PTK_KEY_SIZE         = 0x8000012c;
    public static final int VENDOR_PTK_ISSUER_STR       = 0x80000130;
    public static final int VENDOR_PTK_SUBJECT_STR      = 0x80000131;
    public static final int VENDOR_PTK_SERIAL_NUMBER_INT = 0x80000132;
    public static final int VENDOR_PTK_RECORD_COUNT     = 0x80000136;
    public static final int VENDOR_PTK_RECORD_NUMBER    = 0x80000137;
    public static final int VENDOR_PTK_PURGE            = 0x80000139;
    public static final int VENDOR_PTK_EVENT_LOG_FULL   = 0x8000013a;
    public static final int VENDOR_PTK_SECURITY_MODE    = 0x80000140;
    public static final int VENDOR_PTK_TRANSPORT_MODE   = 0x80000141;
    public static final int VENDOR_PTK_BATCH            = 0x80000142;
    public static final int VENDOR_PTK_HW_STATUS        = 0x80000143;
    public static final int VENDOR_PTK_FREE_MEM         = 0x80000144;
    public static final int VENDOR_PTK_TAMPER_CMD       = 0x80000145;
    public static final int VENDOR_PTK_DATE_OF_MANUFACTURE = 0x80000146;
    public static final int VENDOR_PTK_HALT_CMD         = 0x80000147;
    public static final int VENDOR_PTK_APPLICATION_COUNT = 0x80000148;
    public static final int VENDOR_PTK_FW_VERSION       = 0x80000149;
    public static final int VENDOR_PTK_RESCAN_PERIPHERALS_CMD = 0x8000014a;
    public static final int VENDOR_PTK_RTC_AAC_ENABLED  = 0x8000014b;
    public static final int VENDOR_PTK_RTC_AAC_GUARD_SECONDS = 0x8000014c;
    public static final int VENDOR_PTK_RTC_AAC_GUARD_COUNT = 0x8000014d;
    public static final int VENDOR_PTK_RTC_AAC_GUARD_DURATION = 0x8000014e;
    public static final int VENDOR_PTK_HW_EXT_INFO_STR  = 0x8000014f;
    public static final int VENDOR_PTK_SLOT_ID          = 0x80000151;
    public static final int VENDOR_PTK_MAX_SESSIONS     = 0x80000155;
    public static final int VENDOR_PTK_MIN_PIN_LEN      = 0x80000156;
    public static final int VENDOR_PTK_MAX_PIN_FAIL     = 0x80000158;
    public static final int VENDOR_PTK_FLAGS            = 0x80000159;
    public static final int VENDOR_PTK_VERIFY_OS        = 0x80000170;
    public static final int VENDOR_PTK_VERSION          = 0x80000181;
    public static final int VENDOR_PTK_MANUFACTURER     = 0x80000182;
    public static final int VENDOR_PTK_BUILD_DATE       = 0x80000183;
    public static final int VENDOR_PTK_FINGERPRINT      = 0x80000184;
    public static final int VENDOR_PTK_ROM_SPACE        = 0x80000185;
    public static final int VENDOR_PTK_RAM_SPACE        = 0x80000186;
    public static final int VENDOR_PTK_FM_STATUS        = 0x80000187;
    public static final int VENDOR_PTK_DELETE_FM        = 0x80000188;
    public static final int VENDOR_PTK_FM_STARTUP_STATUS = 0x80000189;
    public static final int VENDOR_PTK_CERTIFICATE_START_TIME = 0x80000190;
    public static final int VENDOR_PTK_CERTIFICATE_END_TIME = 0x80000191;
    public static final int VENDOR_PTK_PKI_ATTRIBUTE_BER_ENCODED = 0x80000230;
    public static final int VENDOR_PTK_HIFACE_MASTER    = 0x80000250;
    public static final int VENDOR_PTK_CKA_SEED         = 0x80000260;
    public static final int VENDOR_PTK_CKA_COUNTER      = 0x80000261;
    public static final int VENDOR_PTK_CKA_H_VALUE      = 0x80000262;
    public static final int VENDOR_PTK_ENUM_ATTRIBUTE   = 0x0000ffff;
    
    /** Maps from int value to String description (variable name). */
    public static final Map<Integer, String> I2S = new HashMap<Integer, String>();
    static {
        try {
            Field[] fields = CKA.class.getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                if (fields[i].getType() == int.class) {
                    I2S.put(fields[i].getInt(null), fields[i].getName());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
