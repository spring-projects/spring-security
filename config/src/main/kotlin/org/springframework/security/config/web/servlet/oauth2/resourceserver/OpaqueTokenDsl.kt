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

package org.springframework.security.config.web.servlet.oauth2.resourceserver

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.web.servlet.SecurityMarker
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector

/**
 * A Kotlin DSL to configure opaque token Resource Server Support using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property introspectionUri the URI of the Introspection endpoint.
 * @property introspector the [OpaqueTokenIntrospector] to use.
 */
@SecurityMarker
class OpaqueTokenDsl {
    private var _introspectionUri: String? = null
    private var _introspector: OpaqueTokenIntrospector? = null
    private var clientCredentials: Pair<String, String>? = null

    var introspectionUri: String?
        get() = _introspectionUri
        set(value) {
            _introspectionUri = value
            _introspector = null
        }
    var introspector: OpaqueTokenIntrospector?
        get() = _introspector
        set(value) {
            _introspector = value
            _introspectionUri = null
            clientCredentials = null
        }


    /**
     * Configures the credentials for Introspection endpoint.
     *
     * @param clientId the clientId part of the credentials.
     * @param clientSecret the clientSecret part of the credentials.
     */
    fun introspectionClientCredentials(clientId: String, clientSecret: String) {
        clientCredentials = Pair(clientId, clientSecret)
        _introspector = null
    }

    internal fun get(): (OAuth2ResourceServerConfigurer<HttpSecurity>.OpaqueTokenConfigurer) -> Unit {
        return { opaqueToken ->
            introspectionUri?.also { opaqueToken.introspectionUri(introspectionUri) }
            introspector?.also { opaqueToken.introspector(introspector) }
            clientCredentials?.also { opaqueToken.introspectionClientCredentials(clientCredentials!!.first, clientCredentials!!.second) }
        }
    }
}
