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
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import com.gdssecurity.editors.BTPWebSocketMessageEditor;

/**
 * Class to implement a WebSocketMessageEditorProvider, which will create new tabs on each BlazorPack websocket message
 */
public class BTPWebSocketMessageEditorProvider implements WebSocketMessageEditorProvider {

    private final MontoyaApi _montoya;

    /**
     * Construct a BTPWebSocketMessageEditorProvider
     * @param api - an instance of the Montoya API
     */
    public BTPWebSocketMessageEditorProvider(MontoyaApi api) {
        this._montoya = api;
    }

    /**
     * Returns a newly created WebSocket message editor for each in-scope BlazorPack message.
     * @param editorContext - what mode the created editor should implement.
     * @return the newly created editor object
     */
    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorContext) {
        return new BTPWebSocketMessageEditor(this._montoya, editorContext.editorMode());
    }
}
