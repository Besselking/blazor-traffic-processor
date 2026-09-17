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
import com.gdssecurity.helpers.BTPHistoryAssembler;
import com.gdssecurity.helpers.BTPMessageCache;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.awt.Component;
import java.nio.charset.StandardCharsets;

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
    // Set when the displayed content is not a re-serializable view of exactly this websocket message
    private boolean readOnlyView;

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
        if (this.readOnlyView || !this.editor.isModified()) {
            // A reassembled or undecoded view does not correspond to this one websocket message, so it is
            // never written back
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
        this.readOnlyView = false;
        byte[] payload = webSocketMessage.payload().getBytes();

        // The common case: the message stands on its own and is editable
        String json = this.blazorHelper.blazorUnpackToJsonString(payload);
        if (json != null) {
            this.editor.setContents(ByteArray.byteArray(json));
            return;
        }

        this.readOnlyView = true;

        // Otherwise it may be part of a message spanning several websocket messages, which the proxy reassembles
        BTPMessageCache.Entry entry = this.messageCache.resolve(payload);
        if (entry != null) {
            String note = entry.fragmentCount() > 1
                    ? String.format(BTPConstants.REASSEMBLED_NOTE, entry.fragmentCount())
                    : BTPConstants.PARTIAL_NOTE;
            this.editor.setContents(ByteArray.byteArray(describe(note, new JSONArray(entry.json()))));
            return;
        }

        // The first message of each direction is the SignalR handshake, which is not BlazorPack at all
        if (isHandshake(payload)) {
            this.editor.setContents(ByteArray.byteArray(
                    describe(BTPConstants.HANDSHAKE_NOTE, new String(payload, StandardCharsets.UTF_8).trim())));
            return;
        }

        // Burp does not pass every piece of a fragmented message to the proxy handler, so the live stream can
        // be missing the rest of this one. The WebSockets history does have them, so rebuild it from there.
        BTPHistoryAssembler.Result rebuilt = BTPHistoryAssembler.rebuild(this._montoya, this.blazorHelper, webSocketMessage);
        if (rebuilt != null) {
            for (byte[] fragment : rebuilt.fragments()) {
                this.messageCache.put(fragment, rebuilt.json(), rebuilt.fragmentCount());
            }
            String note = rebuilt.fragmentCount() > 1
                    ? String.format(BTPConstants.REASSEMBLED_NOTE, rebuilt.fragmentCount())
                    : BTPConstants.PARTIAL_NOTE;
            this.editor.setContents(ByteArray.byteArray(describe(note, new JSONArray(rebuilt.json()))));
            return;
        }

        // Say so rather than showing nothing, so a message BTP cannot make sense of is still explained
        this.logging.logToError("[-] setMessage - Unable to deserialize the selected websocket message.");
        this.editor.setContents(ByteArray.byteArray(describe(BTPConstants.UNDECODABLE_NOTE, toHex(payload))));
    }

    /**
     * Wraps content that is not a plain editable message with a note explaining what it is
     * @param note - the explanation to show
     * @param content - the content to show beneath it
     * @return the JSON text to display
     */
    private static String describe(String note, Object content) {
        JSONObject wrapper = new JSONObject();
        wrapper.put(BTPConstants.REASSEMBLED_NOTE_KEY, note);
        if (content instanceof JSONArray) {
            wrapper.put(BTPConstants.REASSEMBLED_MESSAGES_KEY, content);
        } else {
            wrapper.put(BTPConstants.RAW_BYTES_KEY, content);
        }
        return wrapper.toString(3);
    }

    /**
     * Checks whether a payload is a SignalR handshake record rather than a BlazorPack message
     * @param payload - the websocket message payload
     * @return true if it looks like a handshake
     */
    private static boolean isHandshake(byte[] payload) {
        return payload.length > 1
                && (payload[0] & 0xFF) == '{'
                && payload[payload.length - 1] == BTPConstants.RECORD_SEPARATOR;
    }

    /**
     * Renders a payload as a hex string
     * @param payload - the bytes to render
     * @return the hex representation
     */
    private static String toHex(byte[] payload) {
        StringBuilder hex = new StringBuilder();
        for (byte b : payload) {
            hex.append(String.format(BTPConstants.HEX_FORMAT, b));
        }
        return hex.toString();
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
        byte[] payload = webSocketMessage.payload().getBytes();
        if (webSocketMessage.upgradeRequest() == null || webSocketMessage.upgradeRequest().url() == null) {
            // Without the upgrade request there is no way to tell this is a Blazor connection, so fall back to
            // what the payload itself says rather than offering the tab on every websocket in Burp
            return this.blazorHelper.isBlazorPack(payload) || this.messageCache.resolve(payload) != null;
        }
        if (!webSocketMessage.upgradeRequest().url().contains(BTPConstants.BLAZOR_WS_URL)) {
            return false;
        }
        // Any message on a Blazor websocket gets the tab. A message that cannot be deserialized on its own is
        // usually part of one split across several, and silently hiding the tab makes that look like a bug.
        return true;
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
