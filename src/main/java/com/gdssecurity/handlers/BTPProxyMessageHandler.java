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
import com.gdssecurity.helpers.BlazorHelper;

/**
 * Class to handle highlighting BlazorPack frames on a proxied WebSocket.
 * Frames are passed through untouched - tampering happens in the "BTP" WebSocket editor tab.
 */
public class BTPProxyMessageHandler implements ProxyMessageHandler {

    private final Logging _logging;
    private final BlazorHelper blazorHelper;

    /**
     * Constructor for the proxy message handler
     * @param montoyaApi - an instance of the Burp Montoya APIs
     */
    public BTPProxyMessageHandler(MontoyaApi montoyaApi) {
        this._logging = montoyaApi.logging();
        this.blazorHelper = new BlazorHelper(montoyaApi);
    }

    /**
     * Handle a binary frame as it arrives at the proxy, highlighting it if it holds BlazorPack messages
     * @param interceptedBinaryMessage - the intercepted binary websocket message
     * @return - the un-modified message, following the current interception rules
     */
    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
        highlight(interceptedBinaryMessage);
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
     * Highlights a websocket message in Cyan when it carries BlazorPack data
     * @param message - the intercepted binary message to annotate
     */
    private void highlight(InterceptedBinaryMessage message) {
        try {
            if (message.payload() != null
                    && message.payload().length() != 0
                    && this.blazorHelper.isBlazorPack(message.payload().getBytes())) {
                message.annotations().setHighlightColor(HighlightColor.CYAN);
            }
        } catch (Exception e) {
            this._logging.logToError("[-] highlight - An unexpected error occurred while highlighting a websocket message: " + e.getMessage());
        }
    }
}
