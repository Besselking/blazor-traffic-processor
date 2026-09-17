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
package com.gdssecurity.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;

import java.awt.Component;

/**
 * Class to implement the "BTP" editor tab for proxied WebSocket messages.
 * The tab renders the BlazorPack frame as JSON and re-serializes any edits back into BlazorPack.
 */
public class BTPWebSocketMessageEditor implements ExtensionProvidedWebSocketMessageEditor {

    private final MontoyaApi _montoya;
    private final Logging logging;
    private final BlazorHelper blazorHelper;
    private final WebSocketMessageEditor editor;
    private WebSocketMessage message;

    /**
     * Constructs a new BTPWebSocketMessageEditor object
     * @param api - an instance of the Montoya API
     * @param editorMode - options for the editor object
     */
    public BTPWebSocketMessageEditor(MontoyaApi api, EditorMode editorMode) {
        this._montoya = api;
        this.logging = api.logging();
        this.blazorHelper = new BlazorHelper(api);
        this.editor = editorMode == EditorMode.READ_ONLY
                ? api.userInterface().createWebSocketMessageEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createWebSocketMessageEditor();
    }

    /**
     * Converts the JSON in the editor back to BlazorPack, called when another tab is selected
     * Just return the original payload if the editor was not modified
     * @return - a ByteArray holding the BlazorPacked websocket payload
     */
    @Override
    public ByteArray getMessage() {
        if (!this.editor.isModified()) {
            return this.message == null ? ByteArray.byteArray(new byte[0]) : this.message.payload();
        }
        ByteArray contents = this.editor.getContents();
        if (contents == null || contents.length() == 0) {
            this.logging.logToError("[-] getMessage: The selected editor body is empty/null.");
            return this.message == null ? ByteArray.byteArray(new byte[0]) : this.message.payload();
        }
        try {
            JSONArray messages = new JSONArray(contents.toString());
            byte[] newPayload = this.blazorHelper.blazorPack(messages);
            if (newPayload == null) {
                this.logging.logToError("[-] getMessage - Failed to serialize the provided JSON to BlazorPack.");
                return this.message.payload();
            }
            return ByteArray.byteArray(newPayload);
        } catch (JSONException e) {
            this.logging.logToError("[-] getMessage - JSONException while parsing JSON array: " + e.getMessage());
        } catch (Exception e) {
            this.logging.logToError("[-] getMessage - Unexpected exception while serializing the message: " + e.getMessage());
        }
        return this.message.payload();
    }

    /**
     * Converts the BlazorPack payload to JSON, called when the "BTP" tab is clicked
     * @param webSocketMessage - the websocket message to deserialize from BlazorPack to JSON
     */
    @Override
    public void setMessage(WebSocketMessage webSocketMessage) {
        this.message = webSocketMessage;
        String json = this.blazorHelper.blazorUnpackToJsonString(webSocketMessage.payload().getBytes());
        if (json == null) {
            this.logging.logToError("[-] setMessage - Unable to deserialize the selected websocket message.");
            this.editor.setContents(webSocketMessage.payload());
            return;
        }
        this.editor.setContents(ByteArray.byteArray(json));
    }

    /**
     * Checks to see if the "BTP" tab should appear for a given websocket message
     * @param webSocketMessage - the websocket message to check
     * @return true if it should be enabled, false otherwise
     */
    @Override
    public boolean isEnabledFor(WebSocketMessage webSocketMessage) {
        if (webSocketMessage == null || webSocketMessage.payload() == null || webSocketMessage.payload().length() == 0) {
            return false;
        }
        if (webSocketMessage.upgradeRequest() == null || webSocketMessage.upgradeRequest().url() == null) {
            return false;
        }
        if (!webSocketMessage.upgradeRequest().url().contains(BTPConstants.BLAZOR_WS_URL)) {
            return false;
        }
        if (!this._montoya.scope().isInScope(webSocketMessage.upgradeRequest().url())) {
            return false;
        }
        return this.blazorHelper.isBlazorPack(webSocketMessage.payload().getBytes());
    }

    /**
     * Gets the caption for the editor tab
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component for the editor tab
     * @return the editor's UI component
     */
    @Override
    public Component uiComponent() {
        return this.editor.uiComponent();
    }

    /**
     * Get the selected data within the editor
     * @return the editor's selection object, or null if nothing is selected
     */
    @Override
    public Selection selectedData() {
        return this.editor.selection().orElse(null);
    }

    /**
     * Check if the editor has been modified. If not, getMessage returns the original payload.
     * @return true if modified, false otherwise
     */
    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }
}
