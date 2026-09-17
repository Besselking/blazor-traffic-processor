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
 * The first message in each direction is the SignalR handshake, which is a JSON record terminated by 0x1E rather
 * than a length-prefixed BlazorPack message. It has to be consumed as such: its leading '{' would otherwise be read
 * as a length prefix and throw the rest of the stream out of alignment.
 *
 * Instances are per connection and per direction, and are safe to call from Burp's proxy threads.
 */
public class BlazorReassembler {

    // Ceiling on a single buffered message, so a desynchronised or non-BlazorPack stream cannot grow without bound
    private static final int MAX_BUFFERED_BYTES = 32 * 1024 * 1024;
    // A VarInt length prefix is at most 5 bytes for a 32-bit value
    private static final int MAX_VARINT_BYTES = 5;
    // The SignalR handshake is a JSON record closed by this separator
    private static final byte RECORD_SEPARATOR = 0x1E;
    private static final int OPENING_BRACE = 0x7B;
    // No handshake record is anywhere near this long, so past it we are looking at something else
    private static final int MAX_HANDSHAKE_BYTES = 4096;
    // A message that has not completed after this many payloads is never going to
    private static final int MAX_PAYLOADS_PER_MESSAGE = 256;

    private byte[] buffer = new byte[0];
    private final List<byte[]> pendingFragments = new ArrayList<>();
    // The handshake is only ever the first record of a direction
    private boolean expectHandshake = true;
    private int payloadsWhilePending;
    private String desyncNotice;

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

        if (this.buffer.length > 0) {
            // A websocket cannot interleave the data frames of two messages, so a payload that is itself a
            // complete BlazorPack message proves that what we are still holding was never the start of one.
            // Without this check a single bad length prefix swallows every message that follows it, for good.
            if (looksLikeCompleteMessages(payload)) {
                this.desyncNotice = "discarded " + this.buffer.length
                        + " buffered byte(s) that never formed a message; resynchronised on a later one";
                reset();
            } else if (++this.payloadsWhilePending > MAX_PAYLOADS_PER_MESSAGE) {
                this.desyncNotice = "discarded " + this.buffer.length + " buffered byte(s) after "
                        + MAX_PAYLOADS_PER_MESSAGE + " websocket messages without completing one";
                reset();
            }
        }

        this.buffer = concat(this.buffer, payload);
        this.pendingFragments.add(payload);

        int consumed = 0;
        while (true) {
            if (this.expectHandshake) {
                int handshakeLength = handshakeLength(this.buffer, consumed);
                if (handshakeLength == -1) {
                    break; // The handshake record has not arrived in full yet
                }
                if (handshakeLength > 0) {
                    // Drop the handshake: it is not BlazorPack and has nothing to deserialize
                    consumed += handshakeLength;
                    this.expectHandshake = false;
                    this.pendingFragments.clear();
                    this.pendingFragments.add(payload);
                    continue;
                }
                this.expectHandshake = false; // Not a handshake, so treat it as a normal message
            }

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
            if (!isPlausibleBody(this.buffer, consumed + prefixLength)) {
                // Every BlazorPack message is a MessagePack array. Anything else means the stream is no longer
                // aligned, and walking on would emit nonsense, so drop what is buffered and start over.
                reset();
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
            this.payloadsWhilePending = 0;
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
     * Reports how much of a message is buffered while the rest of it arrives
     * @return the number of buffered bytes
     */
    public synchronized int pendingBytes() {
        return this.buffer.length;
    }

    /**
     * Discards any partially buffered message
     */
    public synchronized void reset() {
        this.buffer = new byte[0];
        this.pendingFragments.clear();
        this.payloadsWhilePending = 0;
    }

    /**
     * Returns and clears any note about the stream having been resynchronised, for the caller to log
     * @return the note, or null if the stream has stayed in step
     */
    public synchronized String consumeDesyncNotice() {
        String notice = this.desyncNotice;
        this.desyncNotice = null;
        return notice;
    }

    /**
     * Checks whether a payload is, on its own, one or more whole BlazorPack messages and nothing else.
     * A payload carrying the middle of a message effectively never satisfies this: it starts at an arbitrary
     * byte, so its supposed length prefix has to land exactly on the end of the payload and every body has to
     * open with a MessagePack array header.
     * @param payload - the websocket payload to test
     * @return true if the payload stands alone as whole messages
     */
    public static boolean looksLikeCompleteMessages(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return false;
        }
        int offset = 0;
        int messages = 0;
        while (offset < payload.length) {
            long prefix = readVarInt(payload, offset);
            if (prefix == -1) {
                return false;
            }
            int prefixLength = (int) (prefix >>> 32);
            int messageLength = (int) prefix;
            if (messageLength <= 0 || prefixLength > MAX_VARINT_BYTES) {
                return false;
            }
            if (!isPlausibleBody(payload, offset + prefixLength)) {
                return false;
            }
            offset += prefixLength + messageLength;
            if (offset > payload.length) {
                return false; // Runs past the end, so this is not a self-contained payload
            }
            messages++;
        }
        return messages > 0;
    }

    /**
     * Measures a leading SignalR handshake record, if that is what the buffer starts with
     * @param data - the buffer to inspect
     * @param offset - the offset to inspect at
     * @return the record length including its separator, 0 if this is not a handshake, or -1 if more bytes are needed
     */
    private static int handshakeLength(byte[] data, int offset) {
        if (offset >= data.length) {
            return -1;
        }
        if ((data[offset] & 0xFF) != OPENING_BRACE) {
            return 0;
        }
        // A 123-byte BlazorPack message also starts with 0x7B, so let the byte after it decide: a real message
        // body opens with a MessagePack array header, a handshake with JSON
        if (offset + 1 < data.length && isPlausibleBody(data, offset + 1)) {
            return 0;
        }
        for (int i = offset; i < data.length && i - offset < MAX_HANDSHAKE_BYTES; i++) {
            if (data[i] == RECORD_SEPARATOR) {
                return (i - offset) + 1;
            }
        }
        return data.length - offset >= MAX_HANDSHAKE_BYTES ? 0 : -1;
    }

    /**
     * Checks whether a message body starts the way a BlazorPack message must, with a MessagePack array header
     * @param data - the buffer to inspect
     * @param offset - the offset the body starts at
     * @return true if the body is plausible, or if there are not yet enough bytes to tell
     */
    private static boolean isPlausibleBody(byte[] data, int offset) {
        if (offset >= data.length) {
            return true; // Not enough bytes to judge; the caller waits for more
        }
        int header = data[offset] & 0xFF;
        // fixarray with at least one element, or the 16/32-bit array headers
        return (header >= 0x91 && header <= 0x9F) || header == 0xDC || header == 0xDD;
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
