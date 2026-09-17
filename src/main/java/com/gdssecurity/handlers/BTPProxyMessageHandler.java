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
package com.gdssecurity.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.websocket.Direction;
import com.gdssecurity.helpers.BTPMessageCache;
import com.gdssecurity.helpers.BTPSettings;
import com.gdssecurity.helpers.BlazorHelper;
import com.gdssecurity.helpers.BlazorReassembler;

import java.util.List;

/**
 * Class to handle BlazorPack frames on a proxied WebSocket.
 *
 * Frames are passed through untouched - tampering happens in the "BTP" WebSocket editor tab. Alongside that, each
 * direction is treated as a byte stream so that BlazorPack messages split across several WebSocket messages can be
 * reassembled and deserialized; the result is cached for the editor to pick up.
 */
public class BTPProxyMessageHandler implements ProxyMessageHandler {

    private final Logging _logging;
    private final BlazorHelper blazorHelper;
    private final BTPMessageCache messageCache;
    private final BTPSettings settings;
    // One stream per direction: a message is only ever split across messages travelling the same way
    private final BlazorReassembler clientToServer = new BlazorReassembler();
    private final BlazorReassembler serverToClient = new BlazorReassembler();

    /**
     * Constructor for the proxy message handler
     * @param montoyaApi - an instance of the Burp Montoya APIs
     * @param messageCache - the shared cache that the editor tab reads reassembled messages from
     * @param settings - the BTP settings, consulted for whether to log every message
     */
    public BTPProxyMessageHandler(MontoyaApi montoyaApi, BTPMessageCache messageCache, BTPSettings settings) {
        this._logging = montoyaApi.logging();
        this.blazorHelper = new BlazorHelper(montoyaApi);
        this.messageCache = messageCache;
        this.settings = settings;
    }

    /**
     * Handle a binary frame as it arrives at the proxy, reassembling and highlighting BlazorPack messages
     * @param interceptedBinaryMessage - the intercepted binary websocket message
     * @return - the un-modified message, following the current interception rules
     */
    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
        process(interceptedBinaryMessage);
        return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
    }

    /**
     * Handle a binary frame right before it leaves the proxy
     * Note: not utilized, the frame is forwarded as-is (possibly after editing in the BTP tab)
     * @param interceptedBinaryMessage - the intercepted binary websocket message
     * @return - the un-modified message
     */
    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
        return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
    }

    /**
     * Handle a text frame as it arrives at the proxy
     * Note: BlazorPack is a binary protocol, text frames are left alone
     * @param interceptedTextMessage - the intercepted text websocket message
     * @return - the un-modified message
     */
    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
        return TextMessageReceivedAction.continueWith(interceptedTextMessage);
    }

    /**
     * Handle a text frame right before it leaves the proxy
     * Note: BlazorPack is a binary protocol, text frames are left alone
     * @param interceptedTextMessage - the intercepted text websocket message
     * @return - the un-modified message
     */
    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
        return TextMessageToBeSentAction.continueWith(interceptedTextMessage);
    }

    /**
     * Feeds a websocket message into the reassembler for its direction, caches whatever it completes,
     * and highlights the message if it carries BlazorPack data
     * @param message - the intercepted binary message
     */
    private void process(InterceptedBinaryMessage message) {
        try {
            if (message.payload() == null || message.payload().length() == 0) {
                return;
            }
            byte[] payload = message.payload().getBytes();
            BlazorReassembler reassembler = message.direction() == Direction.CLIENT_TO_SERVER
                    ? this.clientToServer
                    : this.serverToClient;

            List<BlazorReassembler.AssembledMessage> assembled = reassembler.accept(payload);
            int deserialized = 0;
            for (BlazorReassembler.AssembledMessage completed : assembled) {
                String json = this.blazorHelper.blazorUnpackToJsonString(completed.message());
                if (json == null) {
                    continue;
                }
                deserialized++;
                // Index every message, not just reassembled ones. Burp can hand us a whole message while the
                // WebSockets history still lists the pieces it arrived in, and the editor is opened against one
                // of those pieces, so it has to be able to find the message any piece belongs to.
                this.messageCache.putMessage(completed.message(), json, completed.fragments().size());
                if (completed.wasSplit()) {
                    for (byte[] fragment : completed.fragments()) {
                        this.messageCache.put(fragment, json, completed.fragments().size());
                    }
                    this._logging.logToOutput("[+] process - Reassembled a BlazorPack message from "
                            + completed.fragments().size() + " websocket messages.");
                }
            }

            // Every binary message on a Blazor websocket is Blazor traffic, whether or not it happens to be a
            // whole message on its own. Highlighting only the ones that complete a message made the pieces of a
            // split message look like unrelated traffic.
            message.annotations().setHighlightColor(HighlightColor.CYAN);

            if (this.settings.isVerboseLoggingEnabled()) {
                this._logging.logToOutput(String.format(
                        "[*] websocket %s %d bytes -> completed %d message(s), deserialized %d, %d byte(s) buffered awaiting the rest",
                        message.direction() == Direction.CLIENT_TO_SERVER ? "to server" : "to client",
                        payload.length, assembled.size(), deserialized, reassembler.pendingBytes()));
            }
        } catch (Exception e) {
            this._logging.logToError("[-] process - An unexpected error occurred while handling a websocket message: " + e.getMessage());
        }
    }
}
