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

package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HttpsRedirectConfigurer
import org.springframework.security.web.PortMapper
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] HTTPS redirection rules using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property portMapper the [PortMapper] that specifies a custom HTTPS port to redirect to.
 */
@SecurityMarker
class HttpsRedirectDsl {
    var requestMatchers: Array<out RequestMatcher>? = null

    internal fun get(): (HttpsRedirectConfigurer<HttpSecurity>) -> Unit {
        return { https ->
            requestMatchers?.also { https.requestMatchers(*requestMatchers!!) }
        }
    }
}
