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
import com.gdssecurity.helpers.BTPMessageCache;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
    private final BTPMessageCache messageCache;
    private WebSocketMessage message;
    // Set when the displayed JSON came from reassembly, i.e. it describes more than just this websocket message
    private boolean reassembled;

    /**
     * Constructs a new BTPWebSocketMessageEditor object
     * @param api - an instance of the Montoya API
     * @param editorMode - options for the editor object
     * @param messageCache - the shared cache holding messages reassembled from several websocket messages
     */
    public BTPWebSocketMessageEditor(MontoyaApi api, EditorMode editorMode, BTPMessageCache messageCache) {
        this._montoya = api;
        this.logging = api.logging();
        this.blazorHelper = new BlazorHelper(api);
        this.messageCache = messageCache;
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
        if (this.reassembled || !this.editor.isModified()) {
            // A reassembled view spans several websocket messages, so it cannot be written back to this one
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
        this.reassembled = false;
        byte[] payload = webSocketMessage.payload().getBytes();

        String json = this.blazorHelper.blazorUnpackToJsonString(payload);
        if (json != null) {
            this.editor.setContents(ByteArray.byteArray(json));
            return;
        }

        // The message does not stand on its own, so it is probably part of one that spans several
        // websocket messages. The proxy reassembles those, so look for the completed message here.
        BTPMessageCache.Entry entry = this.messageCache.get(payload);
        if (entry != null) {
            this.reassembled = true;
            JSONObject wrapper = new JSONObject();
            wrapper.put(BTPConstants.REASSEMBLED_NOTE_KEY, String.format(BTPConstants.REASSEMBLED_NOTE, entry.fragmentCount()));
            wrapper.put(BTPConstants.REASSEMBLED_MESSAGES_KEY, new JSONArray(entry.json()));
            this.editor.setContents(ByteArray.byteArray(wrapper.toString(3)));
            return;
        }

        this.logging.logToError("[-] setMessage - Unable to deserialize the selected websocket message.");
        this.editor.setContents(webSocketMessage.payload());
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
        byte[] payload = webSocketMessage.payload().getBytes();
        // Either the message stands on its own, or it is part of one the proxy reassembled
        return this.blazorHelper.isBlazorPack(payload) || this.messageCache.get(payload) != null;
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
