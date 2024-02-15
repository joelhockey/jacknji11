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

import java.util.ArrayList;
import java.util.List;

/**
 * Encapsulates attribute fetching process.
 * <p>
 * The process iteratively fetches all attributes.
 * It operates either in batch mode or one-by-one.
 * <p>
 * The process is able to use max length of attribute instead of querying for attribute lengths,
 * which can save some time by not issuing additional queries.
 * <p>
 * At worst case it will issue 3 queries to fetch a requested attribute, at best only 1.
 * It is optimized for fetching many attributes at once (batch mode).
 *
 * @author Tomasz Wysocki
 */
class GetAttributeProcess {

    /**
     * Reference to cryptoki interface.
     */
    private final Cryptoki cryptoki;

    /**
     * Session to use for fetching.
     */
    private final long session;

    /**
     * Object to fetch attributes from.
     */
    private final long object;

    /**
     * Array of entries with fetch state.
     */
    private final Entry[] entries;

    /**
     * Indicator of attribute length strategy used for last query.
     * <p>
     * If <code>true</code> then last query used max length of attributes, and it is possible that buffer too small errors will occur.
     * if <code>false</code> then last query lengths were not speculative and too small errors shall not occur.
     */
    private boolean maxLengthUsedInLastQuery;

    /**
     * Indicator for fetching mode.
     * <p>
     * If <code>true</code> then process fetches many attributes in one request.
     * If <code>false</code> then attributes are fetched one by one.
     */
    private final boolean batchMode;

    /**
     * Internal class with state of fetch process for a single attribute
     */
    private static class Entry {

        /**
         * Type of attribute fetched.
         */
        private final long type;

        /**
         * Result of fetching the attribute.
         */
        private CKA cka;

        /**
         * Length of a buffer to use for fetching.
         * if <code>0</code> then length is not known yet, and it will be queried instead of fetching the attribute.
         */
        private int length;

        /**
         * If <code>true</code> then the {@link #length} is actual known length of the attribute.
         * If <code>false</code> then {@link #length} is set heuristically.
         */
        private boolean lengthKnown;

        /**
         * Create new entry for attribute.
         *
         * @param type  of attribute
         * @param maxLength size of buffer to use for fetching, or <code>0</code> if length shall be established first.
         */
        Entry(long type, int maxLength) {
            this.type = type;
            this.length = maxLength;
        }

        /**
         * @return true if length of the attribute is not known but a maximum value will be used.
         */
        public boolean isMaxLength() {
            return !this.lengthKnown && this.length > 0;
        }

        /**
         * Build query for fetching attribute.
         *
         * @return query for fetching attribute
         */
        private CKA query() {
            if (this.length > 0) {
                return CKA.allocate(this.type, this.length);
            } else {
                return CKA.indefinite(this.type);
            }
        }

        /**
         * Check if attribute was fetched.
         *
         * @return true if attribute was fetched.
         */
        public boolean isFetched() {
            return getCka() != null;
        }

        /**
         * Signal that allocation of buffer for fetching was too short.
         */
        public void bufferTooSmall() {
            this.length = 0;
            this.lengthKnown = false;
        }

        /**
         * Set actual length of the attribute as returned from the provider.
         *
         * @param length of the attribute
         */
        public void setKnownLength(int length) {
            this.length = length;
            this.lengthKnown = true;
        }

        /**
         * @return response from the fetch or null if not fetched yet.
         */
        public CKA getCka() {
            return cka;
        }

        /**
         * Set response from the fetch process.
         *
         * @param cka value of the attribute to be used as response.
         */
        public void setCka(CKA cka) {
            this.cka = cka;
        }
    }

    /**
     * Construct new instance of the process.
     *
     * @param cryptoki reference to cryptoki interface
     * @param session to use for fetching
     * @param object to fetch attributes from
     * @param attributeLengthStrategy strategy for getting attribute lengths
     * @param batchMode if true then process fetches many attributes in one request, if false then attributes are fetched one by one
     * @param types array of attributes to fetch
     */
    GetAttributeProcess(Cryptoki cryptoki, long session, long object, AttributeLengthStrategy attributeLengthStrategy, boolean batchMode, long... types) {
        this.cryptoki = cryptoki;
        this.session = session;
        this.object = object;
        this.batchMode = batchMode;
        this.entries = new Entry[types.length];
        for (int i = 0; i < types.length; i++) {
            entries[i] = new Entry(types[i], attributeLengthStrategy.getAttributeLength(types[i]));
        }
    }

    /**
     * Build query for unfetched entries.
     * <p>
     * This method sets as a side effect {@link #maxLengthUsedInLastQuery} to indicate if max lengths were used in the query,
     * which is used upon processing the response to determine if buffer too small errors are expected.
     *
     * @return query for unfetched entries.
     */
    private CKA[] buildQuery() {
        List<CKA> query = new ArrayList<>();
        boolean maxLengthsUsed = false;
        for (Entry entry : entries) {
            if (!entry.isFetched()) {
                maxLengthsUsed |= entry.isMaxLength();
                query.add(entry.query());
                if (!batchMode) {
                    break;
                }
            }
        }
        this.maxLengthUsedInLastQuery = maxLengthsUsed;
        return query.toArray(new CKA[0]);
    }

    /**
     * Get an entry for given attribute type.
     *
     * @param type of attribute
     * @return entry for given attribute type
     * @throws IllegalStateException if no such attribute type is present
     */
    private Entry getEntry(long type) {
        for (Entry entry : entries) {
            if (entry.type == type) {
                return entry;
            }
        }
        throw new IllegalStateException("No such attribute type: " + type);
    }

    /**
     * Main method to fetch attributes.
     *
     * @return fetched attributes
     * @throws CKRException if there is an error fetching attributes
     */
    CKA[] fetch() throws CKRException {

        // this is query template that will be sent to the PKCS#11 interface
        CKA[] query;
        // loop for as long as there is anything to query
        while ((query = buildQuery()).length > 0) {

            // fetch attributes using query
            long rv = cryptoki.GetAttributeValue(session, object, query);

            // if there was an error indicated we need to process it
            if (rv != CKR.OK) {
                processError(rv, query);
            }

            // if we are here it means that there was no actual error,
            // and we can extract available attributes
            processAvailable(query);

            // next iteration will either fetch rest of attributes or there is nothing to fetch
        }

        // return result from fetch process
        return buildResult();
    }

    /**
     * Process error result and response.
     * <p>
     * PKCS11 spec says:
     * <quote>
     * Note that the error codes CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote true errors for C_GetAttributeValue.
     * </quote>
     *
     * @param rv       result of fetch operation
     * @param response response from fetch operation
     * @throws CKRException if there is an actual error fetching attributes
     */
    private void processError(long rv, CKA[] response) throws CKRException {
        if (rv == CKR.BUFFER_TOO_SMALL) {
            /*
             This could happen if we are using max length strategy and max lengths are too small.
             We assume here that all unavailable attributes are in fact reason for buffer too small
             which depends on the provider implementation but this is how usually providers behave.
             Even if some of them are actually invalid we will correct that in next iteration.
            */
            bufferTooSmall(response);
        } else if (rv == CKR.ATTRIBUTE_SENSITIVE || rv == CKR.ATTRIBUTE_TYPE_INVALID) {
            /*
             If we have more than one unavailable attribute in response,
             and we have been trying to speculatively use max length for attributes
             then we cannot really tell if those attributes are invalid or buffer was too small.
             Therefore, we will revert to querying for lengths first
             and then fetching too small attributes in next iteration.
             If there were no too small attributes we shall know that as well in next iteration
             in which case it shall be the last one.
            */
            if (countUnavailable(response) > 1 && maxLengthUsedInLastQuery) {
                bufferTooSmall(response);
            } else {
                attributesInvalid(response);
            }
        } else {
            // any other error will be thrown as an exception
            throw new CKRException("Error fetching " + listUnavailable(response) + " attributes, rv = "+rv, rv);
        }
    }

    private String listUnavailable(CKA[] templ) {
        StringBuilder sb = new StringBuilder();
        for (CKA cka : templ) {
            if (cka.ulValueLen == CK.UNAVAILABLE_INFORMATION) {
                sb.append(cka.type).append(", ");
            }
        }
        return sb.toString();
    }

    private int countUnavailable(CKA[] templ) {
        int count = 0;
        for (CKA cka : templ) {
            if (cka.ulValueLen == CK.UNAVAILABLE_INFORMATION) {
                count++;
            }
        }
        return count;
    }

    /**
     * @return build result from fetch process.
     */
    private CKA[] buildResult() {
        CKA[] result = new CKA[entries.length];
        for (int i = 0; i < entries.length; i++) {
            result[i] = entries[i].getCka();
        }
        return result;
    }

    /**
     * Process available attributes from the response.
     * <p>
     * Either an attribute is fetched or its length is now known.
     *
     * @param response to extract attributes from.
     */
    private void processAvailable(CKA[] response) {
        for (CKA cka : response) {
            Entry entry = getEntry(cka.type);
            // valid attribute has length of 0, or it has a value
            if (cka.ulValueLen == 0 || (cka.ulValueLen > 0 && cka.pValue != null)) {
                // attribute is now fetched
                entry.setCka(cka);
            } else if (cka.ulValueLen > 0) {
                // pValue is null but attribute size is now known
                entry.setKnownLength((int) cka.ulValueLen);
            }
        }
    }

    /**
     * Process unavailable attributes from the response as "buffer too small".
     * <p>
     * This will reset sizes all attributes that are unavailable to 0, causing their lengths to be
     * queried first before fetching.
     *
     * @param response to extract attributes from.
     */
    private void bufferTooSmall(CKA[] response) {
        for (CKA cka : response) {
            Entry entry = getEntry(cka.type);
            if (cka.ulValueLen == CK.UNAVAILABLE_INFORMATION) {
                entry.bufferTooSmall();
            }
        }
    }

    /**
     * Process unavailable attributes from the response as invalid.
     * <p>
     * This will use the resulting unavailable attributes as results (that are invalid).
     *
     * @param response to extract attributes from.
     */
    private void attributesInvalid(CKA[] response) {
        for (CKA cka : response) {
            Entry entry = getEntry(cka.type);
            if (cka.ulValueLen == CK.UNAVAILABLE_INFORMATION) {
                entry.setCka(cka);
            }
        }
    }
}
