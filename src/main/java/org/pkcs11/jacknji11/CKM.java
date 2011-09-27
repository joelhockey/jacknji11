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

import java.util.HashMap;
import java.util.Map;

/**
 * CKM_? constants and CK_MECHANISM struct wrapper.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKM {

    public static final long RSA_PKCS_KEY_PAIR_GEN       = 0x00000000;
    public static final long RSA_PKCS                    = 0x00000001;
    public static final long RSA_9796                    = 0x00000002;
    public static final long RSA_X_509                   = 0x00000003;
    public static final long MD2_RSA_PKCS                = 0x00000004;
    public static final long MD5_RSA_PKCS                = 0x00000005;
    public static final long SHA1_RSA_PKCS               = 0x00000006;
    public static final long RIPEMD128_RSA_PKCS          = 0x00000007;
    public static final long RIPEMD160_RSA_PKCS          = 0x00000008;
    public static final long RSA_PKCS_OAEP               = 0x00000009;
    public static final long RSA_X9_31_KEY_PAIR_GEN      = 0x0000000a;
    public static final long RSA_X9_31                   = 0x0000000b;
    public static final long SHA1_RSA_X9_31              = 0x0000000c;
    public static final long RSA_PKCS_PSS                = 0x0000000d;
    public static final long SHA1_RSA_PKCS_PSS           = 0x0000000e;
    public static final long DSA_KEY_PAIR_GEN            = 0x00000010;
    public static final long DSA                         = 0x00000011;
    public static final long DSA_SHA1                    = 0x00000012;
    public static final long DH_PKCS_KEY_PAIR_GEN        = 0x00000020;
    public static final long DH_PKCS_DERIVE              = 0x00000021;
    public static final long X9_42_DH_KEY_PAIR_GEN       = 0x00000030;
    public static final long X9_42_DH_DERIVE             = 0x00000031;
    public static final long X9_42_DH_HYBRID_DERIVE      = 0x00000032;
    public static final long X9_42_MQV_DERIVE            = 0x00000033;
    public static final long SHA256_RSA_PKCS             = 0x00000040;
    public static final long SHA384_RSA_PKCS             = 0x00000041;
    public static final long SHA512_RSA_PKCS             = 0x00000042;
    public static final long SHA256_RSA_PKCS_PSS         = 0x00000043;
    public static final long SHA384_RSA_PKCS_PSS         = 0x00000044;
    public static final long SHA512_RSA_PKCS_PSS         = 0x00000045;
    public static final long SHA224_RSA_PKCS             = 0x00000046;
    public static final long SHA224_RSA_PKCS_PSS         = 0x00000047;
    public static final long RC2_KEY_GEN                 = 0x00000100;
    public static final long RC2_ECB                     = 0x00000101;
    public static final long RC2_CBC                     = 0x00000102;
    public static final long RC2_MAC                     = 0x00000103;
    public static final long RC2_MAC_GENERAL             = 0x00000104;
    public static final long RC2_CBC_PAD                 = 0x00000105;
    public static final long RC4_KEY_GEN                 = 0x00000110;
    public static final long RC4                         = 0x00000111;
    public static final long DES_KEY_GEN                 = 0x00000120;
    public static final long DES_ECB                     = 0x00000121;
    public static final long DES_CBC                     = 0x00000122;
    public static final long DES_MAC                     = 0x00000123;
    public static final long DES_MAC_GENERAL             = 0x00000124;
    public static final long DES_CBC_PAD                 = 0x00000125;
    public static final long DES2_KEY_GEN                = 0x00000130;
    public static final long DES3_KEY_GEN                = 0x00000131;
    public static final long DES3_ECB                    = 0x00000132;
    public static final long DES3_CBC                    = 0x00000133;
    public static final long DES3_MAC                    = 0x00000134;
    public static final long DES3_MAC_GENERAL            = 0x00000135;
    public static final long DES3_CBC_PAD                = 0x00000136;
    public static final long CDMF_KEY_GEN                = 0x00000140;
    public static final long CDMF_ECB                    = 0x00000141;
    public static final long CDMF_CBC                    = 0x00000142;
    public static final long CDMF_MAC                    = 0x00000143;
    public static final long CDMF_MAC_GENERAL            = 0x00000144;
    public static final long CDMF_CBC_PAD                = 0x00000145;
    public static final long DES_OFB64                   = 0x00000150;
    public static final long DES_OFB8                    = 0x00000151;
    public static final long DES_CFB64                   = 0x00000152;
    public static final long DES_CFB8                    = 0x00000153;
    public static final long MD2                         = 0x00000200;
    public static final long MD2_HMAC                    = 0x00000201;
    public static final long MD2_HMAC_GENERAL            = 0x00000202;
    public static final long MD5                         = 0x00000210;
    public static final long MD5_HMAC                    = 0x00000211;
    public static final long MD5_HMAC_GENERAL            = 0x00000212;
    public static final long SHA_1                       = 0x00000220;
    public static final long SHA_1_HMAC                  = 0x00000221;
    public static final long SHA_1_HMAC_GENERAL          = 0x00000222;
    public static final long RIPEMD128                   = 0x00000230;
    public static final long RIPEMD128_HMAC              = 0x00000231;
    public static final long RIPEMD128_HMAC_GENERAL      = 0x00000232;
    public static final long RIPEMD160                   = 0x00000240;
    public static final long RIPEMD160_HMAC              = 0x00000241;
    public static final long RIPEMD160_HMAC_GENERAL      = 0x00000242;
    public static final long SHA256                      = 0x00000250;
    public static final long SHA256_HMAC                 = 0x00000251;
    public static final long SHA256_HMAC_GENERAL         = 0x00000252;
    public static final long SHA384                      = 0x00000260;
    public static final long SHA384_HMAC                 = 0x00000261;
    public static final long SHA384_HMAC_GENERAL         = 0x00000262;
    public static final long SHA512                      = 0x00000270;
    public static final long SHA512_HMAC                 = 0x00000271;
    public static final long SHA512_HMAC_GENERAL         = 0x00000272;
    public static final long SECURID_KEY_GEN             = 0x00000280;
    public static final long SECURID                     = 0x00000282;
    public static final long HOTP_KEY_GEN                = 0x00000290;
    public static final long HOTP                        = 0x00000291;
    public static final long ACTI                        = 0x000002a0;
    public static final long ACTI_KEY_GEN                = 0x000002a1;
    public static final long CAST_KEY_GEN                = 0x00000300;
    public static final long CAST_ECB                    = 0x00000301;
    public static final long CAST_CBC                    = 0x00000302;
    public static final long CAST_MAC                    = 0x00000303;
    public static final long CAST_MAC_GENERAL            = 0x00000304;
    public static final long CAST_CBC_PAD                = 0x00000305;
    public static final long CAST3_KEY_GEN               = 0x00000310;
    public static final long CAST3_ECB                   = 0x00000311;
    public static final long CAST3_CBC                   = 0x00000312;
    public static final long CAST3_MAC                   = 0x00000313;
    public static final long CAST3_MAC_GENERAL           = 0x00000314;
    public static final long CAST3_CBC_PAD               = 0x00000315;
    public static final long CAST5_KEY_GEN               = 0x00000320;
    public static final long CAST5_ECB                   = 0x00000321;
    public static final long CAST5_CBC                   = 0x00000322;
    public static final long CAST5_MAC                   = 0x00000323;
    public static final long CAST5_MAC_GENERAL           = 0x00000324;
    public static final long CAST5_CBC_PAD               = 0x00000325;
    public static final long CAST128_KEY_GEN             = 0x00000320;
    public static final long CAST128_ECB                 = 0x00000321;
    public static final long CAST128_CBC                 = 0x00000322;
    public static final long CAST128_MAC                 = 0x00000323;
    public static final long CAST128_MAC_GENERAL         = 0x00000324;
    public static final long CAST128_CBC_PAD             = 0x00000325;
    public static final long RC5_KEY_GEN                 = 0x00000330;
    public static final long RC5_ECB                     = 0x00000331;
    public static final long RC5_CBC                     = 0x00000332;
    public static final long RC5_MAC                     = 0x00000333;
    public static final long RC5_MAC_GENERAL             = 0x00000334;
    public static final long RC5_CBC_PAD                 = 0x00000335;
    public static final long IDEA_KEY_GEN                = 0x00000340;
    public static final long IDEA_ECB                    = 0x00000341;
    public static final long IDEA_CBC                    = 0x00000342;
    public static final long IDEA_MAC                    = 0x00000343;
    public static final long IDEA_MAC_GENERAL            = 0x00000344;
    public static final long IDEA_CBC_PAD                = 0x00000345;
    public static final long GENERIC_SECRET_KEY_GEN      = 0x00000350;
    public static final long CONCATENATE_BASE_AND_KEY    = 0x00000360;
    public static final long CONCATENATE_BASE_AND_DATA   = 0x00000362;
    public static final long CONCATENATE_DATA_AND_BASE   = 0x00000363;
    public static final long XOR_BASE_AND_DATA           = 0x00000364;
    public static final long EXTRACT_KEY_FROM_KEY        = 0x00000365;
    public static final long SSL3_PRE_MASTER_KEY_GEN     = 0x00000370;
    public static final long SSL3_MASTER_KEY_DERIVE      = 0x00000371;
    public static final long SSL3_KEY_AND_MAC_DERIVE     = 0x00000372;
    public static final long SSL3_MASTER_KEY_DERIVE_DH   = 0x00000373;
    public static final long TLS_PRE_MASTER_KEY_GEN      = 0x00000374;
    public static final long TLS_MASTER_KEY_DERIVE       = 0x00000375;
    public static final long TLS_KEY_AND_MAC_DERIVE      = 0x00000376;
    public static final long TLS_MASTER_KEY_DERIVE_DH    = 0x00000377;
    public static final long SSL3_MD5_MAC                = 0x00000380;
    public static final long SSL3_SHA1_MAC               = 0x00000381;
    public static final long MD5_KEY_DERIVATION          = 0x00000390;
    public static final long MD2_KEY_DERIVATION          = 0x00000391;
    public static final long SHA1_KEY_DERIVATION         = 0x00000392;
    public static final long SHA256_KEY_DERIVATION       = 0x00000393;
    public static final long SHA384_KEY_DERIVATION       = 0x00000394;
    public static final long SHA512_KEY_DERIVATION       = 0x00000395;
    public static final long PBE_MD2_DES_CBC             = 0x000003a0;
    public static final long PBE_MD5_DES_CBC             = 0x000003a1;
    public static final long PBE_MD5_CAST_CBC            = 0x000003a2;
    public static final long PBE_MD5_CAST3_CBC           = 0x000003a3;
    public static final long PBE_MD5_CAST5_CBC           = 0x000003a4;
    public static final long PBE_MD5_CAST128_CBC         = 0x000003a4;
    public static final long PBE_SHA1_CAST5_CBC          = 0x000003a5;
    public static final long PBE_SHA1_CAST128_CBC        = 0x000003a5;
    public static final long PBE_SHA1_RC4_128            = 0x000003a6;
    public static final long PBE_SHA1_RC4_40             = 0x000003a7;
    public static final long PBE_SHA1_DES3_EDE_CBC       = 0x000003a8;
    public static final long PBE_SHA1_DES2_EDE_CBC       = 0x000003a9;
    public static final long PBE_SHA1_RC2_128_CBC        = 0x000003aa;
    public static final long PBE_SHA1_RC2_40_CBC         = 0x000003ab;
    public static final long PKCS5_PBKD2                 = 0x000003b0;
    public static final long PBA_SHA1_WITH_SHA1_HMAC     = 0x000003c0;
    public static final long WTLS_PRE_MASTER_KEY_GEN     = 0x000003d0;
    public static final long WTLS_MASTER_KEY_DERIVE      = 0x000003d1;
    public static final long WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003d2;
    public static final long WTLS_PRF                    = 0x000003d3;
    public static final long WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003d4;
    public static final long WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003d5;
    public static final long KEY_WRAP_LYNKS              = 0x00000400;
    public static final long KEY_WRAP_SET_OAEP           = 0x00000401;
    public static final long CMS_SIG                     = 0x00000500;
    public static final long KIP_DERIVE                  = 0x00000510;
    public static final long KIP_WRAP                    = 0x00000511;
    public static final long KIP_MAC                     = 0x00000512;
    public static final long CAMELLIA_KEY_GEN            = 0x00000550;
    public static final long CAMELLIA_ECB                = 0x00000551;
    public static final long CAMELLIA_CBC                = 0x00000552;
    public static final long CAMELLIA_MAC                = 0x00000553;
    public static final long CAMELLIA_MAC_GENERAL        = 0x00000554;
    public static final long CAMELLIA_CBC_PAD            = 0x00000555;
    public static final long CAMELLIA_ECB_ENCRYPT_DATA   = 0x00000556;
    public static final long CAMELLIA_CBC_ENCRYPT_DATA   = 0x00000557;
    public static final long CAMELLIA_CTR                = 0x00000558;
    public static final long ARIA_KEY_GEN                = 0x00000560;
    public static final long ARIA_ECB                    = 0x00000561;
    public static final long ARIA_CBC                    = 0x00000562;
    public static final long ARIA_MAC                    = 0x00000563;
    public static final long ARIA_MAC_GENERAL            = 0x00000564;
    public static final long ARIA_CBC_PAD                = 0x00000565;
    public static final long ARIA_ECB_ENCRYPT_DATA       = 0x00000566;
    public static final long ARIA_CBC_ENCRYPT_DATA       = 0x00000567;

    public static final long SKIPJACK_KEY_GEN            = 0x00001000;
    public static final long SKIPJACK_ECB64              = 0x00001001;
    public static final long SKIPJACK_CBC64              = 0x00001002;
    public static final long SKIPJACK_OFB64              = 0x00001003;
    public static final long SKIPJACK_CFB64              = 0x00001004;
    public static final long SKIPJACK_CFB32              = 0x00001005;
    public static final long SKIPJACK_CFB16              = 0x00001006;
    public static final long SKIPJACK_CFB8               = 0x00001007;
    public static final long SKIPJACK_WRAP               = 0x00001008;
    public static final long SKIPJACK_PRIVATE_WRAP       = 0x00001009;
    public static final long SKIPJACK_RELAYX             = 0x0000100a;
    public static final long KEA_KEY_PAIR_GEN            = 0x00001010;
    public static final long KEA_KEY_DERIVE              = 0x00001011;
    public static final long FORTEZZA_TIMESTAMP          = 0x00001020;
    public static final long BATON_KEY_GEN               = 0x00001030;
    public static final long BATON_ECB128                = 0x00001031;
    public static final long BATON_ECB96                 = 0x00001032;
    public static final long BATON_CBC128                = 0x00001033;
    public static final long BATON_COUNTER               = 0x00001034;
    public static final long BATON_SHUFFLE               = 0x00001035;
    public static final long BATON_WRAP                  = 0x00001036;
    public static final long ECDSA_KEY_PAIR_GEN          = 0x00001040;
    public static final long EC_KEY_PAIR_GEN             = 0x00001040;
    public static final long ECDSA                       = 0x00001041;
    public static final long ECDSA_SHA1                  = 0x00001042;
    public static final long ECDH1_DERIVE                = 0x00001050;
    public static final long ECDH1_COFACTOR_DERIVE       = 0x00001051;
    public static final long ECMQV_DERIVE                = 0x00001052;

    public static final long JUNIPER_KEY_GEN             = 0x00001060;
    public static final long JUNIPER_ECB128              = 0x00001061;
    public static final long JUNIPER_CBC128              = 0x00001062;
    public static final long JUNIPER_COUNTER             = 0x00001063;
    public static final long JUNIPER_SHUFFLE             = 0x00001064;
    public static final long JUNIPER_WRAP                = 0x00001065;
    public static final long FASTHASH                    = 0x00001070;
    public static final long AES_KEY_GEN                 = 0x00001080;
    public static final long AES_ECB                     = 0x00001081;
    public static final long AES_CBC                     = 0x00001082;
    public static final long AES_MAC                     = 0x00001083;
    public static final long AES_MAC_GENERAL             = 0x00001084;
    public static final long AES_CBC_PAD                 = 0x00001085;
    public static final long DES_ECB_ENCRYPT_DATA        = 0x00001100;
    public static final long DES_CBC_ENCRYPT_DATA        = 0x00001101;
    public static final long DES3_ECB_ENCRYPT_DATA       = 0x00001102;
    public static final long DES3_CBC_ENCRYPT_DATA       = 0x00001103;
    public static final long AES_ECB_ENCRYPT_DATA        = 0x00001104;
    public static final long AES_CBC_ENCRYPT_DATA        = 0x00001105;

    public static final long DSA_PARAMETER_GEN           = 0x00002000;
    public static final long DH_PKCS_PARAMETER_GEN       = 0x00002001;
    public static final long X9_42_DH_PARAMETER_GEN      = 0x00002002;

    // Vendor defined values
    // Eracom PTK
    public static final long VENDOR_PTK_DSA_SHA1_PKCS    = 0x80000000L + DSA_SHA1 + 1;
    public static final long VENDOR_PTK_KEY_TRANSLATION  = 0x8000001bL;
    public static final long VENDOR_PTK_RC2_ECB_PAD      = 0x80000000L + RC2_ECB;
    public static final long VENDOR_PTK_DES_ECB_PAD      = 0x80000000L + DES_ECB;
    public static final long VENDOR_PTK_DES3_ECB_PAD     = 0x80000000L + DES3_ECB;
    public static final long VENDOR_PTK_DES3_X919_MAC    = 0x80000000L + DES3_MAC;
    public static final long VENDOR_PTK_DES3_X919_MAC_GENERAL = 0x80000000L + DES3_MAC_GENERAL;
    public static final long VENDOR_PTK_DES_MDC_2_PAD1   = 0x80000200L;
    public static final long VENDOR_PTK_ARDFP            = 0x80000204L;
    public static final long VENDOR_PTK_NVB              = 0x80000205L;
    public static final long VENDOR_PTK_CAST5_ECB_PAD    = 0x80000000L + CAST5_ECB;
    public static final long VENDOR_PTK_CAST128_ECB_PAD  = VENDOR_PTK_CAST5_ECB_PAD;
    public static final long VENDOR_PTK_IDEA_ECB_PAD     = 0x80000000L + IDEA_ECB;
    public static final long VENDOR_PTK_XOR_BASE_AND_KEY = 0x80000364L;
    public static final long VENDOR_PTK_DES_BCFv         = 0x8000038eL;
    public static final long VENDOR_PTK_DES3_BCF         = 0x8000038fL;
    public static final long VENDOR_PTK_DES_DERIVE_ECB   = 0x80000500L;
    public static final long VENDOR_PTK_DES_DERIVE_CBC   = 0x80000501L;
    public static final long VENDOR_PTK_DES3_DERIVE_ECB  = 0x80000502L;
    public static final long VENDOR_PTK_DES3_DERIVE_CBC  = 0x80000503L;
    public static final long VENDOR_PTK_DES3_RETAIL_CFB_MAC = 0x80000510L;
    public static final long VENDOR_PTK_SHA1_RSA_PKCS_TIMESTAMP = 0x80000600L;
    public static final long VENDOR_PTK_DECODE_PKCS_7    = 0x80000935L;
    public static final long VENDOR_PTK_DES_OFB64        = 0x80000940L;
    public static final long VENDOR_PTK_DES3_OFB64       = 0x80000941L;
    public static final long VENDOR_PTK_ENCODE_ATTRIBUTES = 0x80000950L;
    public static final long VENDOR_PTK_ENCODE_X_509     = 0x80000951L;
    public static final long VENDOR_PTK_ENCODE_PKCS_10   = 0x80000952L;
    public static final long VENDOR_PTK_DECODE_X_509     = 0x80000953L;
    public static final long VENDOR_PTK_ENCODE_PUBLIC_KEY = 0x80000954L;
    public static final long VENDOR_PTK_ENCODE_X_509_LOCAL_CERT = 0x80000955L;
    public static final long VENDOR_PTK_WRAPKEY_DES3_ECB = 0x80000961L;
    public static final long VENDOR_PTK_WRAPKEY_DES3_CBC = 0x80000962L;
    public static final long VENDOR_PTK_DES3_DDD_CBC     = 0x80000964L;
    public static final long VENDOR_PTK_OS_UPGRADE       = 0x80000990L;
    public static final long VENDOR_PTK_FM_DOWNLOAD      = 0x80000991L;
    public static final long VENDOR_PTK_PP_LOAD_SECRET   = 0x800009a0L;
    public static final long VENDOR_PTK_VISA_CVV         = 0x800009b0L;
    public static final long VENDOR_PTK_ZKA_MDC_2_KEY_DERIVATION = 0x800009c0L;
    public static final long VENDOR_PTK_SEED_KEY_GEN     = 0x800009d0L;
    public static final long VENDOR_PTK_SEED_ECB         = 0x800009d1L;
    public static final long VENDOR_PTK_SEED_CBC         = 0x800009d2L;
    public static final long VENDOR_PTK_SEED_MAC         = 0x800009d3L;
    public static final long VENDOR_PTK_SEED_MAC_GENERAL = 0x800009d4L;
    public static final long VENDOR_PTK_SEED_ECB_PAD     = 0x800009d5L;
    public static final long VENDOR_PTK_SEED_CBC_PAD     = 0x800009d6L;
    public static final long VENDOR_PTK_REPLICATE_TOKEN_RSA_AES = 0x800009e0L;
    public static final long VENDOR_PTK_SECRET_SHARE_WITH_ATTRIBUTES = 0x800009f0L;
    public static final long VENDOR_PTK_SECRET_RECOVER_WITH_ATTRIBUTES = 0x800009f1L;
    public static final long VENDOR_PTK_PKCS12_PBE_EXPORT = 0x800009f2L;
    public static final long VENDOR_PTK_PKCS12_PBE_IMPORT = 0x800009f3L;
    public static final long VENDOR_PTK_ECIES            = 0x80000a00L;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKM.class);
    /**
     * Convert long constant value to name.
     * @param ckm value
     * @return name
     */
    public static final String L2S(long ckm) { return C.l2s(L2S, CKM.class.getSimpleName(), ckm); }

    /** Default params for some mechanisms. */
    public static final Map<Long, byte[]> DEFAULT_PARAMS = new HashMap<Long, byte[]>();
    static {
        byte[] zero8 = new byte[8];
        byte[] zero16 = new byte[16];
        // 8 bytes of zero for default params
        for (long l : new long[] {
            DES_CBC, DES_CBC_PAD,
            DES3_CBC, DES3_CBC_PAD,
            CAST5_CBC, CAST5_CBC_PAD,
            CAST128_CBC, CAST128_CBC_PAD,
            IDEA_CBC, IDEA_CBC_PAD,
            VENDOR_PTK_DES3_X919_MAC, VENDOR_PTK_DES_OFB64, VENDOR_PTK_DES3_OFB64, VENDOR_PTK_DES3_DDD_CBC
        }) {

            DEFAULT_PARAMS.put(l, zero8);
        }
        // 16 bytes of zero for default params
        for (long l : new long[] {AES_CBC, AES_CBC_PAD, VENDOR_PTK_SEED_CBC, VENDOR_PTK_SEED_CBC_PAD}) {
            DEFAULT_PARAMS.put(l, zero16);
        }
        // OAEP default is MGF SHA-1
        DEFAULT_PARAMS.put(RSA_PKCS_OAEP, ULong.ulong2b(new long[] {SHA_1, CKG.MGF1_SHA1, CKG.MGF1_SHA1, 0, 0}));
    }

    public long mechanism;
    public byte[] pParameter;

    /**
     * PKCS#11 CK_MECHANISM struct constructor.
     * @param mechanism CKM_? mechanism.  Use one of the public static final long fields in this class.
     * @param param param for mechanism
     */
    public CKM(long mechanism, byte[] param) {
        this.mechanism = mechanism;
        this.pParameter = param;
    }

    /**
     * PKCS#11 CK_MECHANISM struct constructor using default (possibly no) params.
     * @param mechanism CKM_? mechanism.  Use one of the public static final long fields in this class.
     */
    public CKM(long mechanism) {
        this(mechanism, CKM.DEFAULT_PARAMS.get(mechanism));
    }

    /** @return string */
    public String toString() {
        return String.format("mechanism=0x%08x{%s} paramLen=%d param=%s",
            mechanism, L2S(mechanism), pParameter != null ? pParameter.length : 0,
                    Hex.b2s(pParameter));
    }
}
