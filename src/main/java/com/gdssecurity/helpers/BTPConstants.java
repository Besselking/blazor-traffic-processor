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

import org.json.JSONArray;

import java.util.regex.Pattern;

/**
 * Class holding all BTP constants
 */
public final class BTPConstants {
    // Label and UI Strings
    public static final String EXTENSION_NAME = "BlazorTrafficProcessor";
    public static final String CAPTION = "BTP";
    public static final String SEND_TO_BTP_CAPTION = "Send body to BTP tab";
    public static final String SEND_TO_INT_CAPTION = "Send to Intruder";
    public static final String VERBOSE_CHECKBOX_CAPTION = "Verbose WebSocket logging";
    public static final String VERBOSE_CHECKBOX_TOOLTIP =
            "Logs a line to the extension's Output tab for every proxied WebSocket message: direction, size, "
            + "how many BlazorPack messages it completed, and how many bytes are still buffered awaiting the rest.";
    public static final String PREF_VERBOSE_ENABLED = "btp.verboseWebSocketLogging";
    public static final String DOWNGRADE_CHECKBOX_CAPTION = "Force LongPolling downgrade (WebSockets -> HTTP)";
    public static final String DOWNGRADE_CHECKBOX_TOOLTIP =
            "Legacy mode. When checked, BTP rewrites the Blazor negotiate response so the browser falls back to " +
            "LongPolling over HTTP. Leave unchecked to work with the native WebSocket connection.";
    public static final String LOADED_LOG_MSG = "[+] BTP v1.0 Extension loaded, build ";
    public static final String UNLOADED_LOG_MSG = "[*] BTP v1.0 Extension unloaded.";

    // Patterns and Regexes
    public static final String BLAZOR_URL = "_blazor?id=";
    public static final String BLAZOR_WS_URL = "_blazor";
    public static final String NEGOTIATE_URL = "negotiate?negotiateVersion=";
    public static final Pattern BODY_OFFSET = Pattern.compile("(\r\n\r\n)");
    public static final String HEX_FORMAT = "%02X";

    // Persisted Settings
    public static final String PREF_DOWNGRADE_ENABLED = "btp.downgradeEnabled";
    public static final boolean DEFAULT_DOWNGRADE_ENABLED = false;

    // Downgrade Constants (WS -> HTTP)
    public static final String TRANSPORT_STR = "[{'transport':'ServerSentEvents','transferFormats':['Text']},{'transport':'LongPolling','transferFormats':['Text','Binary']}]";
    public static final JSONArray DOWNGRADED_TRANSPORTS = new JSONArray(TRANSPORT_STR);

    // WebSocket Reassembly Constants
    public static final String REASSEMBLED_NOTE_KEY = "_BTP";
    public static final String REASSEMBLED_MESSAGES_KEY = "Messages";
    public static final String REASSEMBLED_NOTE =
            "Read-only: this BlazorPack message arrived split across %d websocket messages, so edits here cannot be written back to a single one.";
    public static final String HANDSHAKE_NOTE =
            "SignalR handshake record, not a BlazorPack message. Nothing to deserialize.";
    public static final String UNDECODABLE_NOTE =
            "BTP could not deserialize this websocket message. It is most likely part of a message split across "
            + "several websocket messages that BTP did not see in full - reassembly only covers traffic proxied "
            + "while the extension was loaded, so reload the page and try again. The raw bytes are shown unchanged.";
    public static final String RAW_BYTES_KEY = "RawBytes";
    public static final byte RECORD_SEPARATOR = 0x1E;

    // RenderBatch (page delta) Constants
    public static final String RENDER_BATCH_TARGET = "JS.RenderBatch";
    public static final String RENDER_BATCH_KEY = "RenderBatch";

    // HubProtocol Constants
    public static final int INVOCATION = 1;
    public static final int STREAMITEM = 2;
    public static final int COMPLETION = 3;
    public static final int STREAMINVOCATION = 4;
    public static final int CANCELINVOCATION = 5;
    public static final int PING = 6;
    public static final int CLOSE = 7;
    public static final int CANCEL_INVOCATION_ARRAY_HEADER = 3;
    public static final int CLOSE_RECONNECT_ARRAY_HEADER = 3;
    public static final int CLOSE_NORECON_ARRAY_HEADER = 2;
    public static final int COMPLETION_RESULT_HEADER = 5;
    public static final int COMPLETION_NORES_HEADER = 4;
    public static final int RESULT_KIND_ERROR = 1;
    public static final int RESULT_KIND_VOID = 2;
    public static final int RESULT_KIND_NONVOID = 3;
    public static final int DEFAULT_MAP_HEADER = 0;
    public static final int INVOCATION_ARRAY_HEADER = 5;
}
