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

import java.math.BigInteger;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CKA_? constants and wrapper for CK_ATTRIBUTE struct.
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKA {
    private static final Logger LOGGER = LoggerFactory.getLogger(CKA.class);
    public static final long CKF_ARRAY_ATTRIBUTE = 0x40000000;

    public static final long CLASS = 0x00000000;
    public static final long TOKEN = 0x00000001;
    public static final long PRIVATE = 0x00000002;
    public static final long LABEL = 0x00000003;
    public static final long APPLICATION = 0x00000010;
    public static final long VALUE = 0x00000011;
    public static final long OBJECT_ID = 0x00000012;
    public static final long CERTIFICATE_TYPE = 0x00000080;
    public static final long ISSUER = 0x00000081;
    public static final long SERIAL_NUMBER = 0x00000082;
    public static final long AC_ISSUER = 0x00000083;
    public static final long OWNER = 0x00000084;
    public static final long ATTR_TYPES = 0x00000085;
    public static final long TRUSTED = 0x00000086;
    public static final long CERTIFICATE_CATEGORY = 0x00000087;
    public static final long JAVA_MIDP_SECURITY_DOMAIN = 0x00000088;
    public static final long URL = 0x00000089;
    public static final long HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008a;
    public static final long HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008b;
    public static final long CHECK_VALUE = 0x00000090;

    public static final long KEY_TYPE = 0x00000100;
    public static final long SUBJECT = 0x00000101;
    public static final long ID = 0x00000102;
    public static final long SENSITIVE = 0x00000103;
    public static final long ENCRYPT = 0x00000104;
    public static final long DECRYPT = 0x00000105;
    public static final long WRAP = 0x00000106;
    public static final long UNWRAP = 0x00000107;
    public static final long SIGN = 0x00000108;
    public static final long SIGN_RECOVER = 0x00000109;
    public static final long VERIFY = 0x0000010a;
    public static final long VERIFY_RECOVER = 0x0000010b;
    public static final long DERIVE = 0x0000010c;
    public static final long START_DATE = 0x00000110;
    public static final long END_DATE = 0x00000111;
    public static final long MODULUS = 0x00000120;
    public static final long MODULUS_BITS = 0x00000121;
    public static final long PUBLIC_EXPONENT = 0x00000122;
    public static final long PRIVATE_EXPONENT = 0x00000123;
    public static final long PRIME_1 = 0x00000124;
    public static final long PRIME_2 = 0x00000125;
    public static final long EXPONENT_1 = 0x00000126;
    public static final long EXPONENT_2 = 0x00000127;
    public static final long COEFFICIENT = 0x00000128;
    public static final long PRIME = 0x00000130;
    public static final long SUBPRIME = 0x00000131;
    public static final long BASE = 0x00000132;
    public static final long PRIME_BITS = 0x00000133;
    public static final long SUBPRIME_BITS = 0x00000134;
    public static final long VALUE_BITS = 0x00000160;
    public static final long VALUE_LEN = 0x00000161;
    public static final long EXTRACTABLE = 0x00000162;
    public static final long LOCAL = 0x00000163;
    public static final long NEVER_EXTRACTABLE = 0x00000164;
    public static final long ALWAYS_SENSITIVE = 0x00000165;
    public static final long MODIFIABLE = 0x00000170;
    public static final long EC_PARAMS = 0x00000180;
    public static final long EC_POINT = 0x00000181;
    public static final long SECONDARY_AUTH = 0x00000200;
    public static final long AUTH_PIN_FLAGS = 0x00000201;
    public static final long ALWAYS_AUTHENTICATE = 0x00000202;
    public static final long WRAP_WITH_TRUSTED = 0x00000210;
    public static final long WRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000211);
    public static final long UNWRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000212);
    public static final long OTP_FORMAT = 0x00000220;
    public static final long OTP_LENGTH = 0x00000221;
    public static final long OTP_TIME_INTERVAL = 0x00000222;
    public static final long OTP_USER_FRIENDLY_MODE = 0x00000223;
    public static final long OTP_CHALLENGE_REQUIREMENT = 0x00000224;
    public static final long OTP_TIME_REQUIREMENT = 0x00000225;
    public static final long OTP_COUNTER_REQUIREMENT = 0x00000226;
    public static final long OTP_PIN_REQUIREMENT = 0x00000227;
    public static final long OTP_COUNTER = 0x0000022e;
    public static final long OTP_TIME = 0x0000022f;
    public static final long OTP_USER_IDENTIFIER = 0x0000022a;
    public static final long OTP_SERVICE_IDENTIFIER = 0x0000022b;
    public static final long OTP_SERVICE_LOGO = 0x0000022c;
    public static final long OTP_SERVICE_LOGO_TYPE = 0x0000022d;

    public static final long HW_FEATURE_TYPE = 0x00000300;
    public static final long RESET_ON_INIT = 0x00000301;
    public static final long HAS_RESET = 0x00000302;
    public static final long PIXEL_X = 0x00000400;
    public static final long PIXEL_Y = 0x00000401;
    public static final long RESOLUTION = 0x00000402;
    public static final long CHAR_ROWS = 0x00000403;
    public static final long CHAR_COLUMNS = 0x00000404;
    public static final long COLOR = 0x00000405;
    public static final long BITS_PER_PIXEL = 0x00000406;
    public static final long CHAR_SETS = 0x00000480;
    public static final long ENCODING_METHODS = 0x00000481;
    public static final long MIME_TYPES = 0x00000482;
    public static final long MECHANISM_TYPE = 0x00000500;
    public static final long REQUIRED_CMS_ATTRIBUTES = 0x00000501;
    public static final long DEFAULT_CMS_ATTRIBUTES = 0x00000502;
    public static final long SUPPORTED_CMS_ATTRIBUTES = 0x00000503;
    public static final long ALLOWED_MECHANISMS = (CKF_ARRAY_ATTRIBUTE | 0x00000600);

    // Vendor defined values
    // Eracom PTK
    public static final long VENDOR_PTK_USAGE_COUNT = 0x80000101;
    public static final long VENDOR_PTK_TIME_STAMP = 0x80000102;
    public static final long VENDOR_PTK_CHECK_VALUE = 0x80000103;
    public static final long VENDOR_PTK_MECHANISM_LIST = 0x80000104;
    public static final long VENDOR_PTK_SIGN_LOCAL_CERT = 0x80000127;
    public static final long VENDOR_PTK_EXPORT = 0x80000128;
    public static final long VENDOR_PTK_EXPORTABLE = 0x80000129;
    public static final long VENDOR_PTK_DELETABLE = 0x8000012a;
    public static final long VENDOR_PTK_IMPORT = 0x8000012b;
    public static final long VENDOR_PTK_KEY_SIZE = 0x8000012c;
    public static final long VENDOR_PTK_ISSUER_STR = 0x80000130;
    public static final long VENDOR_PTK_SUBJECT_STR = 0x80000131;
    public static final long VENDOR_PTK_SERIAL_NUMBER_INT = 0x80000132;
    public static final long VENDOR_PTK_RECORD_COUNT = 0x80000136;
    public static final long VENDOR_PTK_RECORD_NUMBER = 0x80000137;
    public static final long VENDOR_PTK_PURGE = 0x80000139;
    public static final long VENDOR_PTK_EVENT_LOG_FULL = 0x8000013a;
    public static final long VENDOR_PTK_SECURITY_MODE = 0x80000140;
    public static final long VENDOR_PTK_TRANSPORT_MODE = 0x80000141;
    public static final long VENDOR_PTK_BATCH = 0x80000142;
    public static final long VENDOR_PTK_HW_STATUS = 0x80000143;
    public static final long VENDOR_PTK_FREE_MEM = 0x80000144;
    public static final long VENDOR_PTK_TAMPER_CMD = 0x80000145;
    public static final long VENDOR_PTK_DATE_OF_MANUFACTURE = 0x80000146;
    public static final long VENDOR_PTK_HALT_CMD = 0x80000147;
    public static final long VENDOR_PTK_APPLICATION_COUNT = 0x80000148;
    public static final long VENDOR_PTK_FW_VERSION = 0x80000149;
    public static final long VENDOR_PTK_RESCAN_PERIPHERALS_CMD = 0x8000014a;
    public static final long VENDOR_PTK_RTC_AAC_ENABLED = 0x8000014b;
    public static final long VENDOR_PTK_RTC_AAC_GUARD_SECONDS = 0x8000014c;
    public static final long VENDOR_PTK_RTC_AAC_GUARD_COUNT = 0x8000014d;
    public static final long VENDOR_PTK_RTC_AAC_GUARD_DURATION = 0x8000014e;
    public static final long VENDOR_PTK_HW_EXT_INFO_STR = 0x8000014f;
    public static final long VENDOR_PTK_SLOT_ID = 0x80000151;
    public static final long VENDOR_PTK_MAX_SESSIONS = 0x80000155;
    public static final long VENDOR_PTK_MIN_PIN_LEN = 0x80000156;
    public static final long VENDOR_PTK_MAX_PIN_FAIL = 0x80000158;
    public static final long VENDOR_PTK_FLAGS = 0x80000159;
    public static final long VENDOR_PTK_VERIFY_OS = 0x80000170;
    public static final long VENDOR_PTK_VERSION = 0x80000181;
    public static final long VENDOR_PTK_MANUFACTURER = 0x80000182;
    public static final long VENDOR_PTK_BUILD_DATE = 0x80000183;
    public static final long VENDOR_PTK_FINGERPRINT = 0x80000184;
    public static final long VENDOR_PTK_ROM_SPACE = 0x80000185;
    public static final long VENDOR_PTK_RAM_SPACE = 0x80000186;
    public static final long VENDOR_PTK_FM_STATUS = 0x80000187;
    public static final long VENDOR_PTK_DELETE_FM = 0x80000188;
    public static final long VENDOR_PTK_FM_STARTUP_STATUS = 0x80000189;
    public static final long VENDOR_PTK_CERTIFICATE_START_TIME = 0x80000190;
    public static final long VENDOR_PTK_CERTIFICATE_END_TIME = 0x80000191;
    public static final long VENDOR_PTK_PKI_ATTRIBUTE_BER_ENCODED = 0x80000230;
    public static final long VENDOR_PTK_HIFACE_MASTER = 0x80000250;
    public static final long VENDOR_PTK_CKA_SEED = 0x80000260;
    public static final long VENDOR_PTK_CKA_COUNTER = 0x80000261;
    public static final long VENDOR_PTK_CKA_H_VALUE = 0x80000262;
    public static final long VENDOR_PTK_ENUM_ATTRIBUTE = 0x0000ffff;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKA.class);

    /**
     * Convert long constant value to name.
     *
     * @param cka
     *            value
     * @return name
     */
    public static final String L2S(long cka) {
        return C.l2s(L2S, CKA.class.getSimpleName(), cka);
    }

    public long type;
    public byte[] pValue;
    public long ulValueLen;

    // disallow zero-arg constructor
    private CKA() {
    }

    /**
     * PKCS#11 CK_ATTRIBUTE struct constructor.
     *
     * @param type
     *            CKA_? type. Use one of the public static final long fields in this class.
     * @param value
     *            supports java types Boolean, byte[], Number (long, long), String
     */
    public CKA(long type, Object value) {
        this.type = type;
        if (value == null) {
            pValue = null;
            ulValueLen = 0;
        } else if (value instanceof Boolean) {
            pValue = new byte[] { (Boolean) value ? (byte) 1 : (byte) 0 };
            ulValueLen = 1;
        } else if (value instanceof byte[]) {
            pValue = (byte[]) value;
            ulValueLen = pValue.length;
        } else if (value instanceof BigInteger) {
            byte[] pValue = ((BigInteger) value).toByteArray();
            ulValueLen = pValue.length;
        } else if (value instanceof Number) {
            pValue = ULong.ulong2b(((Number) value).longValue());
            ulValueLen = pValue.length;
        } else if (value instanceof String) {
            pValue = ((String) value).getBytes();
            ulValueLen = pValue.length;
        } else {
            throw new RuntimeException("Unknown att type: " + value.getClass());
        }
    }

    /**
     * PKCS#11 CK_ATTRIBUTE struct constructor with null value.
     *
     * @param type
     *            CKA_? type. Use one of the public static final long fields in this class.
     */
    public CKA(long type) {
        this(type, null);
    }

    /** @return value as byte[] */
    public byte[] getValue() {
        return pValue == null ? null : pValue;
    }

    /** @return value as String */
    public String getValueStr() {
        return pValue == null ? null : new String(pValue);
    }

    /** @return value as Long */
    public Long getValueLong() {
        if (ulValueLen == 0 || pValue == null) {
            return null;
        }
        if (ulValueLen != ULong.ULONG_SIZE.size()) {
            throw new IllegalStateException(
                    String.format(
                        "Method getValueLong called when value is not long type of length %d.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                        ULong.ULONG_SIZE.size(), ulValueLen, type, CKA.L2S.get(type), Hex.b2s(getValue())));
        }
        return ULong.b2ulong(getValue());
    }

    /** @return value as boolean */
    public Boolean getValueBool() {
        if (ulValueLen == 0 || pValue == null) {
            return null;
        }
        if (ulValueLen != 1) {
            throw new IllegalStateException(
                    String.format(
                        "Method getValueBool called when value is not boolean type of length 1.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                        ulValueLen, type, CKA.L2S.get(type), Hex.b2s(getValue())));
        }
        return pValue[0] != 0;
    }

    /** @return value as BigInteger */
    public BigInteger getValueBigInt() {
        return ulValueLen == 0 || pValue == null ? null : new BigInteger(Buf.substring(pValue, 0, (int)ulValueLen));
    }

    /**
     * Dump for debug.
     *
     * @param sb
     *            write to
     */
    public void dump(StringBuilder sb) {
        sb.append(String.format("type=0x%08x{%s} valueLen=%d", type, L2S(type), ulValueLen));

        try {
            switch ((int) type) {
            case (int) CLASS: // lookup CKO
                Long cko = getValueLong();
                sb.append(String.format(" value=0x%08x{%s}", type, cko != null ? CKO.L2S(cko) : "null"));
                return;
            case (int) TOKEN: // boolean
            case (int) PRIVATE:
            case (int) TRUSTED:
            case (int) SENSITIVE:
            case (int) ENCRYPT:
            case (int) DECRYPT:
            case (int) WRAP:
            case (int) UNWRAP:
            case (int) SIGN:
            case (int) SIGN_RECOVER:
            case (int) VERIFY:
            case (int) VERIFY_RECOVER:
            case (int) DERIVE:
            case (int) EXTRACTABLE:
            case (int) LOCAL:
            case (int) NEVER_EXTRACTABLE:
            case (int) ALWAYS_SENSITIVE:
            case (int) MODIFIABLE:
            case (int) ALWAYS_AUTHENTICATE:
            case (int) WRAP_WITH_TRUSTED:
            case (int) RESET_ON_INIT:
            case (int) HAS_RESET:
            case (int) VENDOR_PTK_SIGN_LOCAL_CERT:
            case (int) VENDOR_PTK_EXPORT:
            case (int) VENDOR_PTK_EXPORTABLE:
            case (int) VENDOR_PTK_DELETABLE:
            case (int) VENDOR_PTK_IMPORT:
            case (int) VENDOR_PTK_EVENT_LOG_FULL:
            case (int) VENDOR_PTK_VERIFY_OS:
                Boolean b = getValueBool();
                sb.append(" value=").append(b != null ? b ? "TRUE" : "FALSE" : "null");
                return;
            case (int) LABEL: // escaped printable string
            case (int) APPLICATION:
            case (int) URL:
            case (int) START_DATE:
            case (int) END_DATE:
            case (int) VENDOR_PTK_TIME_STAMP:
            case (int) VENDOR_PTK_ISSUER_STR:
            case (int) VENDOR_PTK_SUBJECT_STR:
            case (int) VENDOR_PTK_DATE_OF_MANUFACTURE:
            case (int) VENDOR_PTK_RTC_AAC_ENABLED:
            case (int) VENDOR_PTK_HW_EXT_INFO_STR:
            case (int) VENDOR_PTK_MANUFACTURER:
            case (int) VENDOR_PTK_BUILD_DATE:
            case (int) VENDOR_PTK_CERTIFICATE_START_TIME:
            case (int) VENDOR_PTK_CERTIFICATE_END_TIME:
                sb.append(" value=").append(Buf.escstr(getValue()));
                return;
            case (int) CERTIFICATE_TYPE: // lookup CKC
                Long ckc = getValueLong();
                sb.append(String.format(" value=0x%08x{%s}", type, ckc != null ? CKC.L2S(ckc) : "null"));
                return;
            case (int) KEY_TYPE: // lookup CKK
                Long ckk = getValueLong();
                sb.append(String.format(" value=0x%08x{%s}", type, ckk != null ? CKK.L2S(ckk) : "null"));
                return;
            case (int) MODULUS_BITS: // long
            case (int) PRIME_BITS:
            case (int) SUBPRIME_BITS:
            case (int) VALUE_BITS:
            case (int) VALUE_LEN:
            case (int) OTP_LENGTH:
            case (int) OTP_TIME_INTERVAL:
            case (int) PIXEL_X:
            case (int) PIXEL_Y:
            case (int) RESOLUTION:
            case (int) CHAR_ROWS:
            case (int) CHAR_COLUMNS:
            case (int) BITS_PER_PIXEL:
            case (int) VENDOR_PTK_USAGE_COUNT:
            case (int) VENDOR_PTK_KEY_SIZE:
            case (int) VENDOR_PTK_RECORD_COUNT:
            case (int) VENDOR_PTK_RECORD_NUMBER:
            case (int) VENDOR_PTK_FREE_MEM:
            case (int) VENDOR_PTK_APPLICATION_COUNT:
            case (int) VENDOR_PTK_RTC_AAC_GUARD_SECONDS:
            case (int) VENDOR_PTK_RTC_AAC_GUARD_COUNT:
            case (int) VENDOR_PTK_RTC_AAC_GUARD_DURATION:
            case (int) VENDOR_PTK_SLOT_ID:
            case (int) VENDOR_PTK_MAX_SESSIONS:
            case (int) VENDOR_PTK_MIN_PIN_LEN:
            case (int) VENDOR_PTK_MAX_PIN_FAIL:
            case (int) VENDOR_PTK_ROM_SPACE:
            case (int) VENDOR_PTK_RAM_SPACE:
            case (int) VENDOR_PTK_CKA_COUNTER:
                sb.append(" value=").append(getValueLong());
                return;
            default: // no default, fall through to hex dump below
            }
        } catch (Exception e) { // unexpected CKA values
            // log warning
            LOGGER.warn("Unexpected CKA values", e);
            // hex dump below
        }

        // hex dump by default or if error parsing other data type
        byte[] value = getValue();
        sb.append('\n');
        Hex.dump(sb, value, 0, (int) ulValueLen, "    ", 32, false);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        dump(sb);
        return sb.toString();
    }
}
