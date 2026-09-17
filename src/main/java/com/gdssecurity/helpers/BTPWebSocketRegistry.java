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

import burp.api.montoya.proxy.websocket.ProxyWebSocket;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to track the Blazor WebSockets that are currently open through the proxy.
 *
 * The proxy sees each connection when it is created, but the repeater acts later, so the live ProxyWebSocket
 * objects have to be kept somewhere a UI action can reach them. Each open Blazor connection is registered here
 * with a small stable id and its upgrade URL, and removed when it closes, so the repeater can offer a current
 * list of connections to send an edited invocation back through.
 */
public class BTPWebSocketRegistry {

    /**
     * One open Blazor WebSocket, as the repeater sees it
     */
    public static class Entry {
        private final long id;
        private final String url;
        private final ProxyWebSocket webSocket;

        Entry(long id, String url, ProxyWebSocket webSocket) {
            this.id = id;
            this.url = url;
            this.webSocket = webSocket;
        }

        /**
         * @return the stable id assigned when the connection was registered
         */
        public long id() {
            return this.id;
        }

        /**
         * @return the connection's upgrade request URL
         */
        public String url() {
            return this.url;
        }

        /**
         * @return the live proxy WebSocket, for sending on
         */
        public ProxyWebSocket webSocket() {
            return this.webSocket;
        }

        /**
         * @return a label for the connection dropdown
         */
        @Override
        public String toString() {
            return "#" + this.id + "  " + this.url;
        }
    }

    private final Map<Long, Entry> entries = new LinkedHashMap<>();
    private long nextId = 1;

    /**
     * Records a newly opened Blazor WebSocket
     * @param url - the connection's upgrade request URL
     * @param webSocket - the live proxy WebSocket
     * @return the id assigned to it, for the message handler to hand back on close
     */
    public synchronized long register(String url, ProxyWebSocket webSocket) {
        long id = this.nextId++;
        this.entries.put(id, new Entry(id, url, webSocket));
        return id;
    }

    /**
     * Removes a connection that has closed
     * @param id - the id returned by register
     */
    public synchronized void remove(long id) {
        this.entries.remove(id);
    }

    /**
     * @return a snapshot of the currently open connections, oldest first
     */
    public synchronized List<Entry> entries() {
        return new ArrayList<>(this.entries.values());
    }

    /**
     * Looks up a connection by id
     * @param id - the connection id
     * @return the entry, or null if it is no longer open
     */
    public synchronized Entry get(long id) {
        return this.entries.get(id);
    }

    /**
     * Finds the most recently registered open connection for a URL
     * @param url - the upgrade request URL to match
     * @return the matching entry, or null if none is open
     */
    public synchronized Entry findByUrl(String url) {
        Entry match = null;
        for (Entry entry : this.entries.values()) {
            if (entry.url().equals(url)) {
                match = entry; // Keep scanning so the newest registration wins
            }
        }
        return match;
    }
}
