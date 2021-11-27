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

import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] Opaque Token Resource Server support using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property introspectionUri the URI of the Introspection endpoint.
 * @property introspector the [ReactiveOpaqueTokenIntrospector] to use.
 */
@ServerSecurityMarker
class ServerOpaqueTokenDsl {
    private var _introspectionUri: String? = null
    private var _introspector: ReactiveOpaqueTokenIntrospector? = null
    private var clientCredentials: Pair<String, String>? = null

    var introspectionUri: String?
        get() = _introspectionUri
        set(value) {
            _introspectionUri = value
            _introspector = null
        }
    var introspector: ReactiveOpaqueTokenIntrospector?
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

    internal fun get(): (ServerHttpSecurity.OAuth2ResourceServerSpec.OpaqueTokenSpec) -> Unit {
        return { opaqueToken ->
            introspectionUri?.also { opaqueToken.introspectionUri(introspectionUri) }
            clientCredentials?.also { opaqueToken.introspectionClientCredentials(clientCredentials!!.first, clientCredentials!!.second) }
            introspector?.also { opaqueToken.introspector(introspector) }
        }
    }
}
