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
package com.gdssecurity.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import com.gdssecurity.helpers.BlazorHelper;
import com.gdssecurity.helpers.BTPHistoryAssembler;
import com.gdssecurity.helpers.BTPWebSocketRegistry;
import com.gdssecurity.views.BTPRepeaterView;
import com.gdssecurity.views.BTPView;
import com.gdssecurity.helpers.BTPConstants;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to handle the menu items in the right-click window under "Extensions"
 */
public class BTPContextMenuItemsProvider implements ContextMenuItemsProvider {

    private MontoyaApi _montoya;
    private Logging _logging;
    private BTPView btpTab;
    private BTPRepeaterView repeaterTab;
    private BTPWebSocketRegistry registry;
    private BlazorHelper blazorHelper;

    /**
     * Construct an instance of the menu provider
     * @param montoyaApi - an instance of the Burpsuite Montoya APIs
     * @param btpTab - an instance of the BTP view, used to send the contents to BTP tab
     * @param repeaterTab - an instance of the BTP Repeater view, used to send an invocation for editing/resending
     * @param registry - the registry of open Blazor WebSockets, used to find the connection a message came from
     */
    public BTPContextMenuItemsProvider(MontoyaApi montoyaApi, BTPView btpTab, BTPRepeaterView repeaterTab,
                                       BTPWebSocketRegistry registry) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.blazorHelper = new BlazorHelper(this._montoya);
        this.btpTab = btpTab;
        this.repeaterTab = repeaterTab;
        this.registry = registry;
    }

    /**
     * Gets called by Burpsuite since this is a registered menu items provider
     * @param event This object can be queried to find out about HTTP request/responses that are associated with the context menu invocation.
     *
     * @return - an arraylist of components to include in the right-click menu
     */
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        ArrayList<Component> menuItems = new ArrayList<>();

        // Send to BTP tab for ad-hoc serialization
        JMenuItem sendToBTP = new JMenuItem();
        sendToBTP.setText(BTPConstants.SEND_TO_BTP_CAPTION);
        sendToBTP.addActionListener(e -> {
            HttpRequestResponse selection;
            // Selected inside the HTTP request/response editor
            if (event.selectedRequestResponses().isEmpty() && event.messageEditorRequestResponse().isPresent()) {
                selection = event.messageEditorRequestResponse().get().requestResponse();
            } else { // Selected on the request/response entry in HTTP history
                selection = event.selectedRequestResponses().get(0);
            }
            this.sendSelectionToBTP(selection);
        });
        menuItems.add(sendToBTP);
        return menuItems;
    }

    /**
     * Handles the selection of "Send body to BTP tab" menu option
     * Sends the body from the selected request/response to editor of BTP tab
     * @param selection - the selected HttpRequestResponse object
     */
    private void sendSelectionToBTP(HttpRequestResponse selection) {
        if (selection.url() != null && !selection.url().contains(BTPConstants.BLAZOR_URL)) {
            this._logging.logToError("[-] sendSelectionToBTP - Selected message is not BlazorPack.");
            return;
        }
        if (selection.request() != null && selection.request().body() != null && selection.request().body().length() != 0) {
            this.btpTab.setEditorText(selection.request().body());
        } else if (selection.response() != null && selection.response().body() != null && selection.response().body().length() != 0) {
            this.btpTab.setEditorText(selection.response().body());
        }
    }

    /**
     * Gets called by Burpsuite when the right-click menu is invoked on a WebSocket message
     * @param event This object can be queried to find out about the WebSocket messages associated with the context menu invocation.
     *
     * @return - an arraylist of components to include in the right-click menu
     */
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        ArrayList<Component> menuItems = new ArrayList<>();

        // Send to BTP tab for ad-hoc serialization
        JMenuItem sendToBTP = new JMenuItem();
        sendToBTP.setText(BTPConstants.SEND_TO_BTP_CAPTION);
        sendToBTP.addActionListener(e -> {
            WebSocketMessage selection;
            // Selected inside the websocket message editor
            if (event.selectedWebSocketMessages().isEmpty() && event.messageEditorWebSocket().isPresent()) {
                selection = event.messageEditorWebSocket().get().webSocketMessage();
            } else if (!event.selectedWebSocketMessages().isEmpty()) { // Selected on an entry in the WebSockets history
                selection = event.selectedWebSocketMessages().get(0);
            } else {
                this._logging.logToError("[-] provideMenuItems - No websocket message selected.");
                return;
            }
            this.sendSelectionToBTP(selection);
        });
        menuItems.add(sendToBTP);

        // Send to the repeater for editing and resending through the live connection
        JMenuItem sendToRepeater = new JMenuItem();
        sendToRepeater.setText(BTPConstants.SEND_TO_REPEATER_CAPTION);
        sendToRepeater.addActionListener(e -> {
            WebSocketMessage selection;
            if (event.selectedWebSocketMessages().isEmpty() && event.messageEditorWebSocket().isPresent()) {
                selection = event.messageEditorWebSocket().get().webSocketMessage();
            } else if (!event.selectedWebSocketMessages().isEmpty()) {
                selection = event.selectedWebSocketMessages().get(0);
            } else {
                this._logging.logToError("[-] provideMenuItems - No websocket message selected.");
                return;
            }
            this.sendSelectionToRepeater(selection);
        });
        menuItems.add(sendToRepeater);
        return menuItems;
    }

    /**
     * Handles "Send invocation to BTP Repeater": deserializes the selected websocket message (reassembling from
     * history if it was split) and loads it into the repeater, selecting the connection it came from
     * @param selection - the selected WebSocketMessage object
     */
    private void sendSelectionToRepeater(WebSocketMessage selection) {
        if (selection.payload() == null || selection.payload().length() == 0) {
            this._logging.logToError("[-] sendSelectionToRepeater - Selected websocket message is empty.");
            return;
        }
        byte[] payload = selection.payload().getBytes();

        // Prefer a standalone decode; fall back to rebuilding a split message from the WebSockets history
        String json = this.blazorHelper.blazorUnpackToJsonString(payload);
        if (json == null) {
            BTPHistoryAssembler.Result rebuilt = BTPHistoryAssembler.rebuild(this._montoya, this.blazorHelper, selection);
            if (rebuilt != null) {
                json = rebuilt.json();
            }
        }
        if (json == null) {
            this._logging.logToError("[-] sendSelectionToRepeater - Could not deserialize the selected message.");
            return;
        }

        BTPWebSocketRegistry.Entry connection = null;
        if (selection.upgradeRequest() != null && selection.upgradeRequest().url() != null) {
            connection = this.registry.findByUrl(selection.upgradeRequest().url());
        }
        this.repeaterTab.loadInvocation(connection, json, selection.direction());
    }

    /**
     * Handles the selection of "Send body to BTP tab" menu option for a websocket message
     * Sends the frame payload to the editor of the BTP tab
     * @param selection - the selected WebSocketMessage object
     */
    private void sendSelectionToBTP(WebSocketMessage selection) {
        if (selection.payload() == null || selection.payload().length() == 0) {
            this._logging.logToError("[-] sendSelectionToBTP - Selected websocket message is empty.");
            return;
        }
        this.btpTab.setEditorText(selection.payload());
    }
}
