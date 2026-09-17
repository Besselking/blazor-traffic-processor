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
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class to remember deserialized BlazorPack messages so the editor can find the one a given WebSocket message
 * belongs to.
 *
 * A BlazorPack message and a WebSocket message are not the same thing, and they come apart in both directions:
 * a message can be split across several WebSocket messages, and the proxy can hand the extension a whole message
 * while the WebSockets history still lists the pieces it arrived in. Either way the editor is opened against one
 * piece and has to find the message it is part of.
 *
 * Lookups therefore work two ways: an exact match on a payload the reassembler saw, and failing that a search of
 * recently deserialized messages for one that contains this payload.
 */
public class BTPMessageCache {

    // Enough to cover the messages a tester is likely to click back through, without holding a session in memory
    private static final int MAX_ENTRIES = 512;
    // Recent whole messages kept for containment lookups
    private static final int MAX_RECENT_MESSAGES = 32;
    // Skip containment indexing for anything implausibly large
    private static final int MAX_INDEXED_MESSAGE_BYTES = 8 * 1024 * 1024;

    private final Map<String, Entry> entries = Collections.synchronizedMap(
            new LinkedHashMap<String, Entry>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private final Deque<Message> recent = new ArrayDeque<>();

    /**
     * Holds the deserialized form of a message, and how it relates to the WebSocket message being viewed
     */
    public static class Entry {
        private final String json;
        private final int fragmentCount;
        private final boolean partial;

        Entry(String json, int fragmentCount, boolean partial) {
            this.json = json;
            this.fragmentCount = fragmentCount;
            this.partial = partial;
        }

        /**
         * @return the JSON representation of the complete message
         */
        public String json() {
            return this.json;
        }

        /**
         * @return how many WebSocket messages the message was split across, or 0 if that is not known
         */
        public int fragmentCount() {
            return this.fragmentCount;
        }

        /**
         * @return true if the viewed WebSocket message is only a part of this message
         */
        public boolean partial() {
            return this.partial;
        }
    }

    /**
     * Holds a whole deserialized message for containment lookups
     */
    private static class Message {
        private final byte[] bytes;
        private final String json;
        private final int fragmentCount;

        Message(byte[] bytes, String json, int fragmentCount) {
            this.bytes = bytes;
            this.json = json;
            this.fragmentCount = fragmentCount;
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
        this.entries.put(key, new Entry(json, fragmentCount, true));
    }

    /**
     * Records a whole deserialized message, so that any WebSocket message displaying part of it can find it
     * @param message - the complete BlazorPack message bytes, length prefix included
     * @param json - the JSON representation of the message
     * @param fragmentCount - how many WebSocket messages it was reassembled from, or 1 if it arrived whole
     */
    public void putMessage(byte[] message, String json, int fragmentCount) {
        if (message == null || message.length == 0 || message.length > MAX_INDEXED_MESSAGE_BYTES) {
            return;
        }
        synchronized (this.recent) {
            this.recent.addFirst(new Message(message, json, fragmentCount));
            while (this.recent.size() > MAX_RECENT_MESSAGES) {
                this.recent.removeLast();
            }
        }
    }

    /**
     * Finds the deserialized message that a given WebSocket payload belongs to
     * @param payload - the raw bytes of a single proxied WebSocket message
     * @return the matching entry, or null if this payload is not part of any message we deserialized
     */
    public Entry resolve(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }
        String key = digest(payload);
        if (key != null) {
            Entry exact = this.entries.get(key);
            if (exact != null) {
                return exact;
            }
        }
        Message[] snapshot;
        synchronized (this.recent) {
            snapshot = this.recent.toArray(new Message[0]);
        }
        for (Message message : snapshot) {
            if (message.bytes.length == payload.length) {
                continue; // The editor deserializes a whole message directly, so it never needs looking up
            }
            if (contains(message.bytes, payload)) {
                return new Entry(message.json, message.fragmentCount, true);
            }
        }
        return null;
    }

    /**
     * Checks whether a message contains a payload verbatim
     * @param haystack - the complete message bytes
     * @param needle - the payload to look for
     * @return true if the payload appears within the message
     */
    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length > haystack.length) {
            return false;
        }
        byte first = needle[0];
        int last = haystack.length - needle.length;
        outer:
        for (int i = 0; i <= last; i++) {
            if (haystack[i] != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
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
