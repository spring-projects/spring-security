/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.asciidoctor.gradle

/**
 * Supported backends.
 *
 * @author Benjamin Muschko
 */
enum AsciidoctorBackend {
    HTML5('html5'), DOCBOOK('docbook'), PDF('pdf')

    private final static Map<String, AsciidoctorBackend> ALL_BACKENDS
    private final String id

    static {
        ALL_BACKENDS = values().collectEntries{ [it.id, it] }.asImmutable()
    }

    private AsciidoctorBackend(String id) {
        this.id = id
    }

    String getId() {
        id
    }

    static boolean isSupported(String name) {
        ALL_BACKENDS.containsKey(name)
    }
}
