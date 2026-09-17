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

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

/**
 * Class holding the user-configurable BTP settings, backed by Burp's extension preferences
 */
public class BTPSettings {

    private final Preferences preferences;

    /**
     * Constructs a BTPSettings object
     * @param api - an instance of the Montoya API
     */
    public BTPSettings(MontoyaApi api) {
        this.preferences = api.persistence().preferences();
    }

    /**
     * Whether BTP should rewrite the Blazor negotiate response to force LongPolling over HTTP.
     * WebSocket messages are now handled natively, so the downgrade is opt-in.
     * @return true if the downgrade is enabled, false otherwise
     */
    public boolean isDowngradeEnabled() {
        Boolean stored = this.preferences.getBoolean(BTPConstants.PREF_DOWNGRADE_ENABLED);
        return stored == null ? BTPConstants.DEFAULT_DOWNGRADE_ENABLED : stored;
    }

    /**
     * Whether every proxied WebSocket message should be logged to the extension's output
     * @return true if verbose logging is enabled, false otherwise
     */
    public boolean isVerboseLoggingEnabled() {
        Boolean stored = this.preferences.getBoolean(BTPConstants.PREF_VERBOSE_ENABLED);
        return stored != null && stored;
    }

    /**
     * Enables or disables verbose WebSocket logging, persisting the choice across Burp restarts
     * @param enabled - true to log every proxied WebSocket message
     */
    public void setVerboseLoggingEnabled(boolean enabled) {
        this.preferences.setBoolean(BTPConstants.PREF_VERBOSE_ENABLED, enabled);
    }

    /**
     * Enables or disables the WS -> HTTP downgrade, persisting the choice across Burp restarts
     * @param enabled - true to force LongPolling, false to leave the negotiation untouched
     */
    public void setDowngradeEnabled(boolean enabled) {
        this.preferences.setBoolean(BTPConstants.PREF_DOWNGRADE_ENABLED, enabled);
    }
}
