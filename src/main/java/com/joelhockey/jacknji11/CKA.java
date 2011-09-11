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

package com.joelhockey.jacknji11;

import java.math.BigInteger;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * CKA_? constants and wrapper for CK_ATTRIBUTE struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKA {
    private static final Log log = LogFactory.getLog(CKA.class);
    public static final int CKF_ARRAY_ATTRIBUTE         = 0x40000000;

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
    public static final int CERTIFICATE_CATEGORY        = 0x00000087;
    public static final int JAVA_MIDP_SECURITY_DOMAIN   = 0x00000088;
    public static final int URL                         = 0x00000089;
    public static final int HASH_OF_SUBJECT_PUBLIC_KEY  = 0x0000008a;
    public static final int HASH_OF_ISSUER_PUBLIC_KEY   = 0x0000008b;
    public static final int CHECK_VALUE                 = 0x00000090;

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
    public static final int SUBPRIME_BITS               = 0x00000134;
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
    public static final int ALWAYS_AUTHENTICATE         = 0x00000202;
    public static final int WRAP_WITH_TRUSTED           = 0x00000210;
    public static final int WRAP_TEMPLATE               = (CKF_ARRAY_ATTRIBUTE|0x00000211);
    public static final int UNWRAP_TEMPLATE             = (CKF_ARRAY_ATTRIBUTE|0x00000212);
    public static final int OTP_FORMAT                 =  0x00000220;
    public static final int OTP_LENGTH                  = 0x00000221;
    public static final int OTP_TIME_INTERVAL           = 0x00000222;
    public static final int OTP_USER_FRIENDLY_MODE      = 0x00000223;
    public static final int OTP_CHALLENGE_REQUIREMENT   = 0x00000224;
    public static final int OTP_TIME_REQUIREMENT        = 0x00000225;
    public static final int OTP_COUNTER_REQUIREMENT     = 0x00000226;
    public static final int OTP_PIN_REQUIREMENT         = 0x00000227;
    public static final int OTP_COUNTER                 = 0x0000022e;
    public static final int OTP_TIME                    = 0x0000022f;
    public static final int OTP_USER_IDENTIFIER         = 0x0000022a;
    public static final int OTP_SERVICE_IDENTIFIER      = 0x0000022b;
    public static final int OTP_SERVICE_LOGO            = 0x0000022c;
    public static final int OTP_SERVICE_LOGO_TYPE       = 0x0000022d;


    public static final int HW_FEATURE_TYPE             = 0x00000300;
    public static final int RESET_ON_INIT               = 0x00000301;
    public static final int HAS_RESET                   = 0x00000302;
    public static final int PIXEL_X                     = 0x00000400;
    public static final int PIXEL_Y                     = 0x00000401;
    public static final int RESOLUTION                  = 0x00000402;
    public static final int CHAR_ROWS                   = 0x00000403;
    public static final int CHAR_COLUMNS                = 0x00000404;
    public static final int COLOR                       = 0x00000405;
    public static final int BITS_PER_PIXEL              = 0x00000406;
    public static final int CHAR_SETS                   = 0x00000480;
    public static final int ENCODING_METHODS            = 0x00000481;
    public static final int MIME_TYPES                  = 0x00000482;
    public static final int MECHANISM_TYPE              = 0x00000500;
    public static final int REQUIRED_CMS_ATTRIBUTES     = 0x00000501;
    public static final int DEFAULT_CMS_ATTRIBUTES      = 0x00000502;
    public static final int SUPPORTED_CMS_ATTRIBUTES    = 0x00000503;
    public static final int ALLOWED_MECHANISMS          = (CKF_ARRAY_ATTRIBUTE|0x00000600);

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
    private static final Map<Integer, String> I2S = C.createI2SMap(CKA.class);

    /**
     * Convert int constant value to name.
     * @param cka value
     * @return name
     */
    public static final String I2S(int cka) { return C.i2s(I2S, CKA.class.getSimpleName(), cka); }

    public int type;
    public Pointer pValue;
    public int ulValueLen;

    // disallow zero-arg constructor
    private CKA() {
    }

    /**
     * PKCS#11 CK_ATTRIBUTE struct constructor.
     * @param type CKA_? type.  Use one of the public static final int fields in this class.
     * @param value supports java types Boolean, byte[], Number (int, long), String
     */
    public CKA(int type, Object value) {
        this.type = type;
        if (value == null) {
            pValue = null;
            ulValueLen = 0;
        } else if (value instanceof Boolean) {
            pValue = new ByteByReference((Boolean) value ? (byte) 1 : (byte) 0).getPointer();
            ulValueLen = 1;
        } else if (value instanceof byte[]) {
            byte[] v = (byte[]) value;
            pValue = new Memory(v.length);
            pValue.write(0, v, 0, v.length);
            ulValueLen = v.length;
        } else if (value instanceof BigInteger) {
            byte[] v = ((BigInteger) value).toByteArray();
            pValue = new Memory(v.length);
            pValue.write(0, v, 0, v.length);
            ulValueLen = v.length;
        } else if (value instanceof Number) {
            pValue = new NativeLongByReference(new NativeLong(((Number) value).longValue())).getPointer();
            ulValueLen = NativeLong.SIZE;
        } else if (value instanceof String) {
            byte[] v = ((String) value).getBytes();
            pValue = new Memory(v.length);
            pValue.write(0, v, 0, v.length);
            ulValueLen = v.length;
        } else {
            throw new RuntimeException("Unknown att type: " + value.getClass());
        }
    }

    /**
     * PKCS#11 CK_ATTRIBUTE struct constructor with null value.
     * @param type CKA_? type.  Use one of the public static final int fields in this class.
     */
    public CKA(int type) {
        this(type, null);
    }

    /** @return value as byte[] */
    public byte[] getValue() { return pValue == null ? null : pValue.getByteArray(0, ulValueLen); }
    /** @return value as String */
    public String getValueStr() { return pValue == null ? null : new String(pValue.getByteArray(0, ulValueLen)); }
    /** @return value as int */
    public Integer getValueInt() {
        if (ulValueLen == 0 || pValue == null) {
            return null;
        }
        if (ulValueLen != NativeLong.SIZE) {
            throw new IllegalStateException(String.format(
                "Method getValueInt called when value is not int type of length %d.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                 NativeLong.SIZE, ulValueLen, type, CKA.I2S.get(type), Hex.b2s(getValue())));
        }
        return NativeLong.SIZE == 4 ? pValue.getInt(0) : (int) pValue.getLong(0);
    }
    /** @return value as boolean */
    public Boolean getValueBool() {
        if (ulValueLen == 0 || pValue == null) {
            return null;
        }
        if (ulValueLen != 1) {
            throw new IllegalStateException(String.format(
                "Method getValueBool called when value is not boolean type of length 1.  Got length: %d, CKA type: 0x%08x(%s), value: %s",
                ulValueLen, type, CKA.I2S.get(type), Hex.b2s(getValue())));
        }
        return pValue.getByte(0) != 0;
    }
    /** @return value as BigInteger */
    public BigInteger getValueBigInt() {
        return ulValueLen == 0 || pValue == null ? null : new BigInteger(getValue());
    }

    /**
     * Dump for debug.
     * @param sb write to
     */
    public void dump(StringBuilder sb) {
        sb.append(String.format("type=0x%08x{%s} valueLen=%d", type, I2S(type), ulValueLen));

        try {
            switch (type) {
            case CLASS: // lookup CKO
                Integer cko = getValueInt();
                sb.append(String.format(" value=0x%08x{%s}", type, cko != null ? CKO.I2S(cko) : "null"));
                return;
            case TOKEN: // boolean
            case PRIVATE:
            case TRUSTED:
            case SENSITIVE:
            case ENCRYPT:
            case DECRYPT:
            case WRAP:
            case UNWRAP:
            case SIGN:
            case SIGN_RECOVER:
            case VERIFY:
            case VERIFY_RECOVER:
            case DERIVE:
            case EXTRACTABLE:
            case LOCAL:
            case NEVER_EXTRACTABLE:
            case ALWAYS_SENSITIVE:
            case MODIFIABLE:
            case ALWAYS_AUTHENTICATE:
            case WRAP_WITH_TRUSTED:
            case RESET_ON_INIT:
            case HAS_RESET:
            case VENDOR_PTK_SIGN_LOCAL_CERT:
            case VENDOR_PTK_EXPORT:
            case VENDOR_PTK_EXPORTABLE:
            case VENDOR_PTK_DELETABLE:
            case VENDOR_PTK_IMPORT:
            case VENDOR_PTK_EVENT_LOG_FULL:
            case VENDOR_PTK_VERIFY_OS:
                Boolean b = getValueBool();
                sb.append(" value=").append(b != null ? b ? "TRUE" : "FALSE" : "null");
                return;
            case LABEL: // escaped printable string
            case APPLICATION:
            case URL:
            case START_DATE:
            case END_DATE:
            case VENDOR_PTK_TIME_STAMP:
            case VENDOR_PTK_ISSUER_STR:
            case VENDOR_PTK_SUBJECT_STR:
            case VENDOR_PTK_DATE_OF_MANUFACTURE:
            case VENDOR_PTK_RTC_AAC_ENABLED:
            case VENDOR_PTK_HW_EXT_INFO_STR:
            case VENDOR_PTK_MANUFACTURER:
            case VENDOR_PTK_BUILD_DATE:
            case VENDOR_PTK_CERTIFICATE_START_TIME:
            case VENDOR_PTK_CERTIFICATE_END_TIME:
                sb.append(" value=").append(Buf.escstr(getValue()));
                return;
            case CERTIFICATE_TYPE: // lookup CKC
                Integer ckc = getValueInt();
                sb.append(String.format(" value=0x%08x{%s}", type, ckc != null ? CKC.I2S(ckc) : "null"));
                return;
            case KEY_TYPE: // lookup CKK
                Integer ckk = getValueInt();
                sb.append(String.format(" value=0x%08x{%s}", type, ckk != null ? CKK.I2S(ckk) : "null"));
                return;
            case MODULUS_BITS: // int
            case PRIME_BITS:
            case SUBPRIME_BITS:
            case VALUE_BITS:
            case VALUE_LEN:
            case OTP_LENGTH:
            case OTP_TIME_INTERVAL:
            case PIXEL_X:
            case PIXEL_Y:
            case RESOLUTION:
            case CHAR_ROWS:
            case CHAR_COLUMNS:
            case BITS_PER_PIXEL:
            case VENDOR_PTK_USAGE_COUNT:
            case VENDOR_PTK_KEY_SIZE:
            case VENDOR_PTK_RECORD_COUNT:
            case VENDOR_PTK_RECORD_NUMBER:
            case VENDOR_PTK_FREE_MEM:
            case VENDOR_PTK_APPLICATION_COUNT:
            case VENDOR_PTK_RTC_AAC_GUARD_SECONDS:
            case VENDOR_PTK_RTC_AAC_GUARD_COUNT:
            case VENDOR_PTK_RTC_AAC_GUARD_DURATION:
            case VENDOR_PTK_SLOT_ID:
            case VENDOR_PTK_MAX_SESSIONS:
            case VENDOR_PTK_MIN_PIN_LEN:
            case VENDOR_PTK_MAX_PIN_FAIL:
            case VENDOR_PTK_ROM_SPACE:
            case VENDOR_PTK_RAM_SPACE:
            case VENDOR_PTK_CKA_COUNTER:
                sb.append(" value=").append(getValueInt());
                return;
            default: // no default, fall through to hex dump below
            }
        } catch (Exception e) { // unexpected CKA values
            // log warning
            log.warn("Unexpected CKA values", e);
            // hex dump below
        }

        // hex dump by default or if error parsing other data type
        byte[] value = getValue();
        Hex.dump(sb, value, 0, ulValueLen, "    ", 32, false);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        dump(sb);
        return sb.toString();
    }
}
