/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.headers

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue

/**
 * A Kotlin DSL to configure the [HttpSecurity] XSS protection header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @author Daniel Garnier-Moiroux
 * @since 5.3
 * @property headerValue the value of the X-XSS-Protection header. OWASP recommends [HeaderValue.DISABLED].
 */
@HeadersSecurityMarker
class XssProtectionConfigDsl {
    var headerValue: HeaderValue? = null

    private var disabled = false

    /**
     * Do not include the X-XSS-Protection header in the response.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.XXssConfig) -> Unit {
        return { xssProtection ->
            headerValue?.also { xssProtection.headerValue(headerValue) }

            if (disabled) {
                xssProtection.disable()
            }
        }
    }
}
