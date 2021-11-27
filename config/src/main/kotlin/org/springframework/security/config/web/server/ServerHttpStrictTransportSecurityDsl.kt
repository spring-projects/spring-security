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

import java.time.Duration

/**
 * A Kotlin DSL to configure the [ServerHttpSecurity] HTTP Strict Transport Security
 * header using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property maxAge he value for the max-age directive of the Strict-Transport-Security
 * header.
 * @property includeSubdomains if true, subdomains should be considered HSTS Hosts too.
 * @property preload if true, preload will be included in HSTS Header.
 */
@ServerSecurityMarker
class ServerHttpStrictTransportSecurityDsl {
    var maxAge: Duration? = null
    var includeSubdomains: Boolean? = null
    var preload: Boolean? = null

    private var disabled = false

    /**
     * Disables the X-Frame-Options response header
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.HeaderSpec.HstsSpec) -> Unit {
        return { hsts ->
            maxAge?.also { hsts.maxAge(maxAge) }
            includeSubdomains?.also { hsts.includeSubdomains(includeSubdomains!!) }
            preload?.also { hsts.preload(preload!!) }
            if (disabled) {
                hsts.disable()
            }
        }
    }
}
