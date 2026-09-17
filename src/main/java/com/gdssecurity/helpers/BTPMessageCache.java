/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.helpers;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class to remember the deserialized form of BlazorPack messages that arrived split over several WebSocket messages.
 *
 * The proxy sees the WebSocket messages in order and can reassemble them, but the editor tab is opened later
 * against a single message, by which time the surrounding ones are no longer at hand. The reassembler stores its
 * result here, keyed by each WebSocket payload that carried part of the message, so that clicking any one of them
 * shows the whole thing.
 *
 * Payloads are keyed by digest rather than held onto, to keep the cache small regardless of message size.
 */
public class BTPMessageCache {

    // Enough to cover the messages a tester is likely to click back through, without holding a session in memory
    private static final int MAX_ENTRIES = 512;

    private final Map<String, Entry> entries = Collections.synchronizedMap(
            new LinkedHashMap<String, Entry>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    /**
     * Holds the deserialized form of a reassembled message
     */
    public static class Entry {
        private final String json;
        private final int fragmentCount;

        Entry(String json, int fragmentCount) {
            this.json = json;
            this.fragmentCount = fragmentCount;
        }

        /**
         * @return the JSON representation of the complete message
         */
        public String json() {
            return this.json;
        }

        /**
         * @return how many WebSocket messages the message was split across
         */
        public int fragmentCount() {
            return this.fragmentCount;
        }
    }

    /**
     * Records the deserialized message against one of the payloads that carried it
     * @param payload - the raw bytes of a single proxied WebSocket message
     * @param json - the JSON representation of the complete message
     * @param fragmentCount - how many WebSocket messages the message was split across
     */
    public void put(byte[] payload, String json, int fragmentCount) {
        String key = digest(payload);
        if (key == null) {
            return;
        }
        this.entries.put(key, new Entry(json, fragmentCount));
    }

    /**
     * Looks up the deserialized message that a given payload formed part of
     * @param payload - the raw bytes of a single proxied WebSocket message
     * @return the cached entry, or null if this payload is not part of a reassembled message
     */
    public Entry get(byte[] payload) {
        String key = digest(payload);
        return key == null ? null : this.entries.get(key);
    }

    /**
     * Hashes a payload to use as a cache key
     * @param payload - the bytes to hash
     * @return the digest as a hex string, or null if the payload is unusable
     */
    private static String digest(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return new BigInteger(1, sha256.digest(payload)).toString(16);
        } catch (NoSuchAlgorithmException e) {
            return null; // SHA-256 is always present on a supported JRE, so this cannot happen in practice
        }
    }
}
