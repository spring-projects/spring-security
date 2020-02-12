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
import org.springframework.security.config.web.servlet.SecurityMarker

/**
 * A Kotlin DSL to configure the [HttpSecurity] XSS protection header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property block whether to specify the mode as blocked
 * @property xssProtectionEnabled if true, the header value will contain a value of 1.
 * If false, will explicitly disable specify that X-XSS-Protection is disabled.
 */
@SecurityMarker
class XssProtectionConfigDsl {
    var block: Boolean? = null
    var xssProtectionEnabled: Boolean? = null

    private var disabled = false

    /**
     * Do not include the X-XSS-Protection header in the response.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.XXssConfig) -> Unit {
        return { xssProtection ->
            block?.also { xssProtection.block(block!!) }
            xssProtectionEnabled?.also { xssProtection.xssProtectionEnabled(xssProtectionEnabled!!) }

            if (disabled) {
                xssProtection.disable()
            }
        }
    }
}
