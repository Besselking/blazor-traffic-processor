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

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Class to reassemble BlazorPack messages that span more than one WebSocket message.
 *
 * A single BlazorPack/SignalR message is not guaranteed to arrive in one WebSocket message: large payloads,
 * render batches in particular, are commonly split. That is exactly why each message carries a VarInt length
 * prefix. Treat one direction of one connection as a byte stream, buffer it, and hand back whole messages
 * as their last byte arrives.
 *
 * Instances are per connection and per direction, and are safe to call from Burp's proxy threads.
 */
public class BlazorReassembler {

    // Ceiling on a single buffered message, so a desynchronised or non-BlazorPack stream cannot grow without bound
    private static final int MAX_BUFFERED_BYTES = 32 * 1024 * 1024;
    // A VarInt length prefix is at most 5 bytes for a 32-bit value
    private static final int MAX_VARINT_BYTES = 5;

    private byte[] buffer = new byte[0];
    private final List<byte[]> pendingFragments = new ArrayList<>();

    /**
     * Holds one fully reassembled BlazorPack message along with the WebSocket payloads it was built from
     */
    public static class AssembledMessage {
        private final byte[] message;
        private final List<byte[]> fragments;

        AssembledMessage(byte[] message, List<byte[]> fragments) {
            this.message = message;
            this.fragments = fragments;
        }

        /**
         * @return the complete BlazorPack message, VarInt length prefix included
         */
        public byte[] message() {
            return this.message;
        }

        /**
         * @return the WebSocket payloads that carried this message, in order
         */
        public List<byte[]> fragments() {
            return Collections.unmodifiableList(this.fragments);
        }

        /**
         * @return true if the message arrived split over more than one WebSocket message
         */
        public boolean wasSplit() {
            return this.fragments.size() > 1;
        }
    }

    /**
     * Feeds one WebSocket payload into the stream
     * @param payload - the raw bytes of a single proxied WebSocket message
     * @return every BlazorPack message completed by this payload, which may be none
     */
    public synchronized List<AssembledMessage> accept(byte[] payload) {
        List<AssembledMessage> completed = new ArrayList<>();
        if (payload == null || payload.length == 0) {
            return completed;
        }
        if ((long) this.buffer.length + payload.length > MAX_BUFFERED_BYTES) {
            // The stream is not what we think it is; drop it rather than buffering indefinitely
            reset();
            return completed;
        }

        this.buffer = concat(this.buffer, payload);
        this.pendingFragments.add(payload);

        int consumed = 0;
        while (true) {
            long prefix = readVarInt(this.buffer, consumed);
            if (prefix == -1) {
                break; // The length prefix itself is not complete yet
            }
            int prefixLength = (int) (prefix >>> 32);
            int messageLength = (int) prefix;
            if (messageLength < 0 || messageLength > MAX_BUFFERED_BYTES) {
                reset(); // Not a BlazorPack stream, or we lost sync with it
                return completed;
            }
            int totalLength = prefixLength + messageLength;
            if (this.buffer.length - consumed < totalLength) {
                break; // Message body is still arriving
            }
            byte[] message = new byte[totalLength];
            System.arraycopy(this.buffer, consumed, message, 0, totalLength);
            completed.add(new AssembledMessage(message, new ArrayList<>(this.pendingFragments)));
            consumed += totalLength;

            // Anything still buffered is a suffix of the payload we were just handed, since everything
            // carried by earlier payloads sat in front of it and has now been consumed
            this.pendingFragments.clear();
            this.pendingFragments.add(payload);
        }

        if (consumed > 0) {
            byte[] remainder = new byte[this.buffer.length - consumed];
            System.arraycopy(this.buffer, consumed, remainder, 0, remainder.length);
            this.buffer = remainder;
            if (remainder.length == 0) {
                this.pendingFragments.clear();
            }
        }
        return completed;
    }

    /**
     * Reports whether a message is part-way through arriving
     * @return true if bytes are buffered that do not yet form a complete message
     */
    public synchronized boolean hasPendingMessage() {
        return this.buffer.length > 0;
    }

    /**
     * Discards any partially buffered message
     */
    public synchronized void reset() {
        this.buffer = new byte[0];
        this.pendingFragments.clear();
    }

    /**
     * Reads a VarInt length prefix
     * @param data - the buffer to read from
     * @param offset - the offset to read at
     * @return the byte count in the high 32 bits and the value in the low 32 bits, or -1 if more bytes are needed
     */
    private static long readVarInt(byte[] data, int offset) {
        int value = 0;
        int shift = 0;
        for (int i = 0; i < MAX_VARINT_BYTES; i++) {
            int index = offset + i;
            if (index >= data.length) {
                return -1; // Incomplete prefix, wait for the next payload
            }
            int b = data[index] & 0xFF;
            value |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return ((long) (i + 1) << 32) | (value & 0xFFFFFFFFL);
            }
            shift += 7;
        }
        return ((long) MAX_VARINT_BYTES << 32) | 0xFFFFFFFFL; // Over-long prefix, caller treats it as a desync
    }

    /**
     * Concatenates two byte arrays
     * @param first - the leading bytes
     * @param second - the trailing bytes
     * @return a new array holding both
     */
    private static byte[] concat(byte[] first, byte[] second) {
        if (first.length == 0) {
            return second.clone();
        }
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }
}
