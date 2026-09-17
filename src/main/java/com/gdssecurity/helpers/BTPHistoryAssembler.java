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

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.Direction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Class to rebuild a split BlazorPack message from Burp's WebSockets history.
 *
 * Burp does not hand an extension every WebSocket message of a fragmented one: a large render batch arrives at
 * the proxy message handler as its first piece only, and the rest never reaches the handler at all. The pieces do
 * all reach the WebSockets history, though, which is what the tester sees listed, so that is where a split message
 * has to be put back together.
 *
 * The history is replayed for the connection and direction the viewed message belongs to, the same way the live
 * stream would have been, and the message that the viewed one forms part of is returned.
 */
public final class BTPHistoryAssembler {

    // Cap the replay so a long-running session does not turn a click into a lengthy scan
    private static final int MAX_HISTORY_ENTRIES = 4000;

    private BTPHistoryAssembler() {
    }

    /**
     * Rebuilds the BlazorPack message that a given WebSocket message forms part of, using Burp's history
     * @param api - an instance of the Montoya API
     * @param blazorHelper - the helper used to deserialize the rebuilt message
     * @param target - the WebSocket message the editor was opened against
     * @return the deserialized message and the number of WebSocket messages it spanned, or null if it could not
     *         be rebuilt
     */
    public static Result rebuild(MontoyaApi api, BlazorHelper blazorHelper, WebSocketMessage target) {
        if (target == null || target.payload() == null || target.payload().length() == 0) {
            return null;
        }
        if (target.upgradeRequest() == null || target.upgradeRequest().url() == null) {
            return null;
        }
        byte[] wanted = target.payload().getBytes();
        String url = target.upgradeRequest().url();
        Direction direction = target.direction();

        List<byte[]> stream = collect(api, url, direction);
        if (stream.size() < 2) {
            return null; // Nothing to piece together
        }

        BlazorReassembler reassembler = new BlazorReassembler();
        for (byte[] payload : stream) {
            for (BlazorReassembler.AssembledMessage assembled : reassembler.accept(payload)) {
                if (!carries(assembled.fragments(), wanted)) {
                    continue;
                }
                String json = blazorHelper.blazorUnpackToJsonString(assembled.message());
                if (json != null) {
                    return new Result(json, assembled.fragments().size(), assembled.fragments());
                }
            }
        }
        return null;
    }

    /**
     * Gathers the payloads of one direction of one connection from the WebSockets history, in order
     * @param api - an instance of the Montoya API
     * @param url - the upgrade request URL identifying the connection
     * @param direction - the direction to gather
     * @return the payloads, oldest first
     */
    private static List<byte[]> collect(MontoyaApi api, String url, Direction direction) {
        List<byte[]> stream = new ArrayList<>();
        List<ProxyWebSocketMessage> history;
        try {
            history = api.proxy().webSocketHistory();
        } catch (Exception e) {
            return stream;
        }
        for (ProxyWebSocketMessage entry : history) {
            try {
                if (entry.direction() != direction || entry.payload() == null || entry.payload().length() == 0) {
                    continue;
                }
                if (entry.upgradeRequest() == null || !url.equals(entry.upgradeRequest().url())) {
                    continue;
                }
                stream.add(entry.payload().getBytes());
                if (stream.size() > MAX_HISTORY_ENTRIES) {
                    stream.remove(0); // Keep the most recent window
                }
            } catch (Exception e) {
                // A history entry that cannot be read is simply skipped
            }
        }
        return stream;
    }

    /**
     * Checks whether any of a message's fragments is the payload being looked for
     * @param fragments - the payloads that carried a reassembled message
     * @param wanted - the payload to look for
     * @return true if one of the fragments matches
     */
    private static boolean carries(List<byte[]> fragments, byte[] wanted) {
        for (byte[] fragment : fragments) {
            if (Arrays.equals(fragment, wanted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Holds a message rebuilt from the WebSockets history
     */
    public static class Result {
        private final String json;
        private final int fragmentCount;
        private final List<byte[]> fragments;

        Result(String json, int fragmentCount, List<byte[]> fragments) {
            this.json = json;
            this.fragmentCount = fragmentCount;
            this.fragments = fragments;
        }

        /**
         * @return the JSON representation of the rebuilt message
         */
        public String json() {
            return this.json;
        }

        /**
         * @return how many WebSocket messages the message spanned
         */
        public int fragmentCount() {
            return this.fragmentCount;
        }

        /**
         * @return the payloads that carried the message
         */
        public List<byte[]> fragments() {
            return this.fragments;
        }
    }
}
