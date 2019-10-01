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
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure the [HttpSecurity] HTTP Strict Transport Security header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property maxAgeInSeconds the value (in seconds) for the max-age directive of the
 * Strict-Transport-Security header.
 * @property requestMatcher the [RequestMatcher] used to determine if the
 * "Strict-Transport-Security" header should be added. If true the header is added,
 * else the header is not added.
 * @property includeSubDomains if true, subdomains should be considered HSTS Hosts too.
 * @property preload if true, preload will be included in HSTS Header.
 */
class HttpStrictTransportSecurityDsl {
    var maxAgeInSeconds: Long? = null
    var requestMatcher: RequestMatcher? = null
    var includeSubDomains: Boolean? = null
    var preload: Boolean? = null

    private var disabled = false

    /**
     * Disable the HTTP Strict Transport Security header.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.HstsConfig) -> Unit {
        return { hsts ->
            maxAgeInSeconds?.also { hsts.maxAgeInSeconds(maxAgeInSeconds!!) }
            requestMatcher?.also { hsts.requestMatcher(requestMatcher) }
            includeSubDomains?.also { hsts.includeSubDomains(includeSubDomains!!) }
            preload?.also { hsts.preload(preload!!) }
            if (disabled) {
                hsts.disable()
            }
        }
    }
}
