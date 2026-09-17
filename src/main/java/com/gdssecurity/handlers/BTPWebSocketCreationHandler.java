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
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BTPMessageCache;

/**
 * Class to detect Blazor WebSockets as they are created through the proxy, and attach a message handler to them
 */
public class BTPWebSocketCreationHandler implements ProxyWebSocketCreationHandler {

    private final MontoyaApi _montoya;
    private final Logging _logging;
    private final BTPMessageCache messageCache;

    /**
     * Constructor for the websocket creation handler
     * @param montoyaApi - an instance of the Burp Montoya APIs
     * @param messageCache - the shared cache that reassembled messages are published to
     */
    public BTPWebSocketCreationHandler(MontoyaApi montoyaApi, BTPMessageCache messageCache) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.messageCache = messageCache;
    }

    /**
     * Called by Burp whenever a new WebSocket is created through the proxy.
     * Registers a BlazorPack-aware message handler on the Blazor connections only.
     * @param webSocketCreation - an object holding the new proxy websocket and its upgrade request
     */
    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        HttpRequest upgradeRequest = webSocketCreation.upgradeRequest();
        if (upgradeRequest == null || upgradeRequest.url() == null) {
            return;
        }
        if (!upgradeRequest.url().contains(BTPConstants.BLAZOR_WS_URL)) {
            return;
        }
        // A handler per websocket, so each connection reassembles its own stream
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(new BTPProxyMessageHandler(this._montoya, this.messageCache));
        this._logging.logToOutput("[+] handleWebSocketCreation - Attached BTP handler to Blazor WebSocket: " + upgradeRequest.url());
    }
}
