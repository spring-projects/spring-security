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

package org.springframework.security.config.web.servlet.headers

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer

/**
 * A Kotlin DSL to configure the [HttpSecurity] X-Frame-Options header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property sameOrigin allow any request that comes from the same origin to frame this
 * application.
 * @property deny deny framing any content from this application.
 */
class FrameOptionsDsl {
    var sameOrigin: Boolean? = null
    var deny: Boolean? = null

    private var disabled = false

    /**
     * Disable the X-Frame-Options header.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.FrameOptionsConfig) -> Unit {
        return { frameOptions ->
            sameOrigin?.also {
                if (sameOrigin!!) {
                    frameOptions.sameOrigin()
                }
            }
            deny?.also {
                if (deny!!) {
                    frameOptions.deny()
                }
            }
            if (disabled) {
                frameOptions.disable()
            }
        }
    }
}
