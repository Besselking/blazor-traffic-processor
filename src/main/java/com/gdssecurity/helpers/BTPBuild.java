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

import java.io.InputStream;
import java.util.Properties;

/**
 * Class exposing the build the loaded jar was produced from, so that a bug report can name it exactly
 */
public final class BTPBuild {

    private static final String RESOURCE = "/btp-build.properties";
    private static final String UNKNOWN = "unknown";

    private BTPBuild() {
    }

    /**
     * Reads the build identifier stamped into the jar at build time
     * @return the short commit the jar was built from, or "unknown" if it could not be read
     */
    public static String id() {
        try (InputStream stream = BTPBuild.class.getResourceAsStream(RESOURCE)) {
            if (stream == null) {
                return UNKNOWN;
            }
            Properties properties = new Properties();
            properties.load(stream);
            return properties.getProperty("build", UNKNOWN);
        } catch (Exception e) {
            return UNKNOWN;
        }
    }
}
