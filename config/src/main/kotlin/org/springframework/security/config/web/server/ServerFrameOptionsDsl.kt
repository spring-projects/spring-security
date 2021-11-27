/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.web.server

import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter

/**
 * A Kotlin DSL to configure the [ServerHttpSecurity] X-Frame-Options header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property mode the X-Frame-Options mode to set in the response header.
 */
@ServerSecurityMarker
class ServerFrameOptionsDsl {
    var mode: XFrameOptionsServerHttpHeadersWriter.Mode? = null

    private var disabled = false

    /**
     * Disables the X-Frame-Options response header
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.HeaderSpec.FrameOptionsSpec) -> Unit {
        return { frameOptions ->
            mode?.also {
                frameOptions.mode(mode)
            }
            if (disabled) {
                frameOptions.disable()
            }
        }
    }
}
