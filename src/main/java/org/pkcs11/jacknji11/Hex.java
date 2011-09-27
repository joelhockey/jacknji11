/*
 * Copyright 2008-2011 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 *
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


/**
 * Hex encoder.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class Hex {
    /** Hex digits.  0123456789abcdef */
    public static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /** Hex string to byte lookup. -1 if non-hex, else hex nibble value. */
    public static final int[] HEX_S2B = new int[256];

    /** Hex byte to string lookup.  returns 2-char hex encoding */
    public static final char[][] HEX_B2S = new char[256][];

    static {
        // init lookup tables
        // Hex S2B
        for (int i = 0; i < HEX_S2B.length; i++) {
            HEX_S2B[i] = -1;
        }
        for (int i = '0'; i <= '9'; i++) {
            HEX_S2B[i] = i - '0';
        }
        for (int i = 'A'; i <= 'F'; i++) {
            HEX_S2B[i] = i - 'A' + 10;
        }
        for (int i = 'a'; i <= 'f'; i++) {
            HEX_S2B[i] = i - 'a' + 10;
        }

        // Hex B2S
        for (int i = 0; i < HEX_DIGITS.length; i++) {
            for (int j = 0; j < HEX_DIGITS.length; j++) {
                HEX_B2S[i * 16 + j] = new char[] { HEX_DIGITS[i], HEX_DIGITS[j] };
            }
        }
    }

    /**
     * Returns lower case hex string representation of byte[].
     * @param buf byte array
     * @return lower case hex encoded string
     */
    public static String b2s(byte[] buf) {
        if (buf == null) return null;
        return b2s(buf, 0, buf.length);
    }

    /**
     * Returns hex string representation of byte[].
     * @param buf byte array
     * @param start pos in buf to start at
     * @param len number of bytes to encode
     * @return hex encoded string
     */
    public static String b2s(byte[] buf, int start, int len) {
        if (buf == null) return null;
        if (start < 0 || start > buf.length) {
            throw new IllegalArgumentException("start index must be between 0 and buf.length [" + buf.length + "].  Got value" + start);
        }

        if (len < 0 || start + len > buf.length) {
            throw new IllegalArgumentException("len must be between 0 and (buf.length - start) ["
                    + buf.length + " - " + start + " = " + (buf.length - start)+ "].  Got value " + len);
        }

        char[] cbuf = new char[len * 2];
        for (int i = 0; i < len; i++) {
            System.arraycopy(HEX_B2S[buf[start + i] & 0xff], 0, cbuf, i * 2, 2);
        }
        return new String(cbuf);
    }

    /**
     * Return 8 char (lower case) hex encoded 32-bit big-endian value
     * @param num number to encode
     * @return 8 char (lower case) hex encoded 32-bit big-endian value
     */
    public static String i2s(int num) {
        char[] cbuf = new char[8];
        // start at rhs
        for (int i = 3; i >= 0; i--) {
            System.arraycopy(Hex.HEX_B2S[num & 0xff] , 0, cbuf, i*2, 2);
            num >>>= 8;
        }
        return new String(cbuf);
    }

    /**
     * Returns byte[] from hex string.
     * Ignores any non-hex chars.
     * Pads extra 0 on end if odd number of hex chars.
     * @param hex hex string e.g. "01ff"
     * @return byte array. e.g. byte[] {1, 255}
     */
    public static byte[] s2b(String hex) {
        if (hex == null) return null;

        byte[] buf = new byte[(hex.length() + 1) / 2];
        int tmpbuf = 0;       // stores nibble
        int bits = 0;         // num of bits in tmpbuf
        int i = 0;            // index into hex
        int j = 0;            // index into result buf
        while (i < hex.length()) {
            int c = Hex.HEX_S2B[hex.charAt(i++) & 0xff];
            // skip non-hex chars
            if (c < 0) {
                continue;
            }
            tmpbuf = tmpbuf | c;
            bits += 4;
            if (bits == 8) {
                buf[j++] = (byte) tmpbuf;
                bits = 0;
            }
            tmpbuf <<= 4;
        }
        // add extra char if exists
        if (bits > 0) {
            buf[j++] = (byte) tmpbuf;
        }

        // return correctly sized byte[]
        if (j == buf.length) {
            return buf;
        } else {
            byte[] smallbuf = new byte[j];
            System.arraycopy(buf, 0, smallbuf, 0, j);
            return smallbuf;
        }
    }

    /**
     * Print hex dump of buf
     * @param buf buf
     * @return hex dump
     */
    public static String dump(byte[] buf) {
        if (buf == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        dump(sb, buf, 0, buf.length, "", 16, false);

        return sb.toString();
    }

    /**
     * Hex dump.
     * @param sb stringbuilder for result
     * @param buf buf to dump
     * @param start start index
     * @param len length
     * @param indent string for indent
     * @param lineLen number of bytes per line (16 or 32 are good choices)
     * @param lineNum if true, line numbers are shown in left col
     */
    public static void dump(StringBuilder sb, byte[] buf, int start, int len,
            String indent, int lineLen, boolean lineNum) {
        if (buf == null) {
            if (lineNum) {
                sb.append(i2s(0)).append(" - ");
            }
            sb.append(indent).append("null");
            return;
        }

        char[] ascii = new char[lineLen];
        int lineOffset = 0; // resets to zero for every line

        int i = start; // index into buf
        int end = start + len;

        while (i < end) {
            // put '\n' and indent to start each line
            if (lineOffset == 0) {
                if (i > start) {
                    sb.append('\n');
                }
                if (lineNum) {
                    sb.append(i2s(i - start)).append(" - ");
                }
                sb.append(indent);

            // put a '-' every 8 chars
            } else if ((lineOffset & 0x7) == 0) {
                sb.append("- ");
            }

            // put ascii into ascii buf
            ascii[lineOffset++] = (buf[i] >= 32 && buf[i] <= 126) ? (char) buf[i] : '.';
            // put hex into sb
            sb.append(HEX_B2S[(buf[(i++)] & 0xff)]).append(' ');

            // put ascii at end of each line
            if (lineOffset == ascii.length) {
                sb.append("  ").append(ascii);
                lineOffset = 0;
            }
        }

        if (lineOffset == 0) {
            return;
        }

        // put fill to line up ascii print
        int missingHex = ascii.length - lineOffset;
        // 3 for each hex, 2 for each '- ', 2 at end
        int fillLen = missingHex * 3 + missingHex / 8 * 2 + 2;

        while (fillLen-- > 0) {
            sb.append(' ');
        }
        sb.append(ascii, 0, lineOffset);
    }
}
