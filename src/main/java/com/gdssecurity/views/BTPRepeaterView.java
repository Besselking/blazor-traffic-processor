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
package com.gdssecurity.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.websocket.Direction;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BTPWebSocketRegistry;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

/**
 * Class to handle the "BTP Repeater" tab, for capturing a client-to-server BlazorPack invocation, editing its
 * JSON, and sending the modified version back through the live WebSocket.
 *
 * The server reconstructs a message from its VarInt length prefix rather than from the WebSocket framing, so an
 * edited invocation can be sent as a single frame however the original arrived. That is what makes a message that
 * was split across several WebSocket messages editable here, where it could not be in the read-only editor tab.
 */
public class BTPRepeaterView extends JComponent {

    private final MontoyaApi _montoya;
    private final Logging _logging;
    private final BTPWebSocketRegistry registry;
    private final BlazorHelper blazorHelper;

    private final JComboBox<BTPWebSocketRegistry.Entry> connectionBox = new JComboBox<>();
    private final JComboBox<String> directionBox = new JComboBox<>(new String[]{
            BTPConstants.DIRECTION_TO_SERVER, BTPConstants.DIRECTION_TO_CLIENT});
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    /**
     * Constructs the repeater view
     * @param montoyaApi - an instance of the Montoya API
     * @param registry - the registry of open Blazor WebSockets to send on
     */
    public BTPRepeaterView(MontoyaApi montoyaApi, BTPWebSocketRegistry registry) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.registry = registry;
        this.blazorHelper = new BlazorHelper(montoyaApi);
        this.editor = montoyaApi.userInterface().createRawEditor();

        setLayout(new BorderLayout(10, 10));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controls.add(new JLabel("Connection:"));
        this.connectionBox.setPrototypeDisplayValue(null);
        controls.add(this.connectionBox);

        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshConnections());
        controls.add(refresh);

        controls.add(new JLabel("Send as:"));
        controls.add(this.directionBox);

        JButton send = new JButton(BTPConstants.REPEATER_SEND_CAPTION);
        send.addActionListener(e -> send());
        controls.add(send);

        JPanel top = new JPanel(new BorderLayout());
        top.add(controls, BorderLayout.NORTH);
        top.add(this.statusLabel, BorderLayout.SOUTH);

        add(top, BorderLayout.NORTH);
        add(this.editor.uiComponent(), BorderLayout.CENTER);

        refreshConnections();
    }

    /**
     * Loads a captured invocation into the repeater, selecting the connection it came from
     * @param connection - the connection the message was seen on, or null if it is no longer open
     * @param json - the deserialized invocation JSON to edit
     * @param direction - the direction the captured message travelled, preselected as the send direction
     */
    public void loadInvocation(BTPWebSocketRegistry.Entry connection, String json, Direction direction) {
        refreshConnections();
        if (connection != null) {
            selectConnection(connection.id());
        }
        this.directionBox.setSelectedItem(direction == Direction.SERVER_TO_CLIENT
                ? BTPConstants.DIRECTION_TO_CLIENT : BTPConstants.DIRECTION_TO_SERVER);
        this.editor.setContents(ByteArray.byteArray(json == null ? "" : json));
        setStatus(connection == null
                ? "Loaded invocation. The originating connection is no longer open - pick another to send on."
                : "Loaded invocation from connection #" + connection.id() + ". Edit the JSON, then Send.");
    }

    /**
     * Repopulates the connection dropdown from the registry, keeping the current selection if it is still open
     */
    private void refreshConnections() {
        Object selected = this.connectionBox.getSelectedItem();
        Long keepId = selected instanceof BTPWebSocketRegistry.Entry ? ((BTPWebSocketRegistry.Entry) selected).id() : null;

        DefaultComboBoxModel<BTPWebSocketRegistry.Entry> model = new DefaultComboBoxModel<>();
        for (BTPWebSocketRegistry.Entry entry : this.registry.entries()) {
            model.addElement(entry);
        }
        this.connectionBox.setModel(model);
        if (keepId != null) {
            selectConnection(keepId);
        }
    }

    /**
     * Selects the dropdown entry for a connection id, if it is present
     * @param id - the connection id to select
     */
    private void selectConnection(long id) {
        for (int i = 0; i < this.connectionBox.getItemCount(); i++) {
            if (this.connectionBox.getItemAt(i).id() == id) {
                this.connectionBox.setSelectedIndex(i);
                return;
            }
        }
    }

    /**
     * Serializes the edited JSON to BlazorPack and sends it on the selected connection
     */
    private void send() {
        Object selected = this.connectionBox.getSelectedItem();
        if (!(selected instanceof BTPWebSocketRegistry.Entry)) {
            setStatus("No open Blazor connection selected. Browse the target through the proxy, then Refresh.");
            return;
        }
        // Re-fetch by id so a connection that closed since the dropdown was populated is caught here
        BTPWebSocketRegistry.Entry entry = this.registry.get(((BTPWebSocketRegistry.Entry) selected).id());
        if (entry == null) {
            refreshConnections();
            setStatus("That connection has closed. Pick another and try again.");
            return;
        }

        ByteArray content = this.editor.getContents();
        if (content == null || content.length() == 0) {
            setStatus("Nothing to send - the editor is empty.");
            return;
        }

        byte[] packed;
        try {
            JSONArray messages = new JSONArray(content.toString());
            packed = this.blazorHelper.blazorPack(messages);
        } catch (JSONException e) {
            setStatus("Could not parse the JSON: " + e.getMessage());
            return;
        } catch (Exception e) {
            this._logging.logToError("[-] BTPRepeaterView.send - Unexpected error serializing: " + e.getMessage());
            setStatus("Could not serialize the invocation: " + e.getMessage());
            return;
        }
        if (packed == null || packed.length == 0) {
            setStatus("Serialization produced no bytes. Check the JSON is a valid BlazorPack message array.");
            return;
        }

        Direction direction = BTPConstants.DIRECTION_TO_CLIENT.equals(this.directionBox.getSelectedItem())
                ? Direction.SERVER_TO_CLIENT
                : Direction.CLIENT_TO_SERVER;
        try {
            entry.webSocket().sendBinaryMessage(ByteArray.byteArray(packed), direction);
        } catch (Exception e) {
            this._logging.logToError("[-] BTPRepeaterView.send - Send failed: " + e.getMessage());
            refreshConnections();
            setStatus("Send failed (the connection may have closed): " + e.getMessage());
            return;
        }
        String arrow = direction == Direction.CLIENT_TO_SERVER ? "to server" : "to client";
        setStatus("Sent " + packed.length + " bytes " + arrow + " on connection #" + entry.id() + ".");
        this._logging.logToOutput("[+] BTPRepeaterView - Sent " + packed.length + " bytes " + arrow
                + " on connection #" + entry.id() + " (" + entry.url() + ")");
    }

    /**
     * Updates the status line
     * @param text - the message to show
     */
    private void setStatus(String text) {
        this.statusLabel.setText(text);
    }
}
