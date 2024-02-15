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

/**
 * Strategy for determining length of attribute value in C_GetAttributeValue request.
 *
 * @author Tomasz Wysocki
 */
public interface AttributeLengthStrategy {

    /**
     * Get expected length of attribute value in C_GetAttributeValue request.
     *
     * @param cka attribute type
     * @return expected length of attribute value or 0 if length should be queried.
     */
    int getAttributeLength(long cka);

    /**
     * Implementation of {@link AttributeLengthStrategy} that is using a list of large attributes
     * and their maximum length as well as a default length for regular attributes.
     * <p>
     * Use to avoid querying length of attributes for every call to C_GetAttributeValue.
     */
    class MaxLengthStrategy implements AttributeLengthStrategy {

        /**
         * Default of 2KB has been established by following facts:
         * Modulus of 15Kb RSA (maximum) is around 2KB.
         * For 7168Kb RSA (which is a practical limit) certificates are about 2K (without extensions).
         * <p>
         * Note: CKA_VALUE is used also for certificate objects, so it is large value as well - which is shame
         * since value is typically used for symmetric keys which are relatively small size.
         * <p>
         * If set to 0 then max length strategy is not used for large attributes.
         */
        public static final int DEFAULT_LARGE_ATTRIBUTE_LENGTH = 2048;

        /**
         * Default 72 (divisible by 8) bytes should be sufficient for most attributes including custom labels and ids
         * as well as EC P-521 compressed public key ( 1B tag | 66B x )
         */
        public static final int DEFAULT_REGULAR_ATTRIBUTE_LENGTH = 72;

        /**
         * Set of large attributes types established to potentially contain large values.
         */
        public static final long[] DEFAULT_LARGE_ATTRIBUTES = new long[]{
                CKA.MODULUS,
                CKA.PRIME_1,
                CKA.PRIME_2,
                CKA.EXPONENT_1,
                CKA.EXPONENT_2,
                CKA.COEFFICIENT,
                CKA.PRIVATE_EXPONENT,
                CKA.VALUE,
                CKA.EC_POINT,
        };

        /**
         * Large attribute types.
         */
        private final long[] largeAttributes;

        /**
         * Length for large attributes, if 0 then max length strategy is not used for large attributes.
         */
        private final int largeAttributeLength;

        /**
         * Default length for attributes, if 0 then max length strategy is not used for regular attributes.
         */
        private final int regularAttributeLength;

        /**
         * Constructor with default values.
         */
        public MaxLengthStrategy() {
            this(DEFAULT_REGULAR_ATTRIBUTE_LENGTH, DEFAULT_LARGE_ATTRIBUTES, DEFAULT_LARGE_ATTRIBUTE_LENGTH);
        }

        /**
         * Constructor with custom values.
         *
         * @param regularAttributeLength length for regular attributes
         * @param largeAttributes        set of large attributes
         * @param largeAttributeLength   length for large attributes
         */
        public MaxLengthStrategy(int regularAttributeLength, long[] largeAttributes, int largeAttributeLength) {
            this.largeAttributes = largeAttributes;
            this.regularAttributeLength = regularAttributeLength;
            this.largeAttributeLength = largeAttributeLength;
        }

        @Override
        public int getAttributeLength(long cka) {
            if (contains(largeAttributes, cka)) {
                return largeAttributeLength;
            } else {
                return regularAttributeLength;
            }
        }

        // simple check if array contains value
        private static boolean contains(long[] array, long value) {
            for (long l : array) {
                if (l == value) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Strategy for querying length of attribute value in C_GetAttributeValue request
     * for every attribute.
     */
    class IndefiniteLengthStrategy implements AttributeLengthStrategy {
        @Override
        public int getAttributeLength(long cka) {
            return 0;
        }
    }
}
