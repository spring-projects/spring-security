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

package org.springframework.security.config.web.servlet.oauth2.login

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest

/**
 * A Kotlin DSL to configure the Authorization Server's Token Endpoint using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property accessTokenResponseClient the client used for requesting the access token credential
 * from the Token Endpoint.
 */
@OAuth2LoginSecurityMarker
class TokenEndpointDsl {
    var accessTokenResponseClient: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>? = null

    internal fun get(): (OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig) -> Unit {
        return { tokenEndpoint ->
            accessTokenResponseClient?.also { tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient) }
        }
    }
}
