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
import org.springframework.security.config.web.servlet.SecurityMarker
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

/**
 * A Kotlin DSL to configure the Authorization Server's Authorization Endpoint using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property baseUri the base URI used for authorization requests.
 * @property authorizationRequestResolver the resolver used for resolving [OAuth2AuthorizationRequest]'s.
 * @property authorizationRequestRepository the repository used for storing [OAuth2AuthorizationRequest]'s.
 */
@SecurityMarker
class AuthorizationEndpointDsl {
    var baseUri: String? = null
    var authorizationRequestResolver: OAuth2AuthorizationRequestResolver? = null
    var authorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null

    internal fun get(): (OAuth2LoginConfigurer<HttpSecurity>.AuthorizationEndpointConfig) -> Unit {
        return { authorizationEndpoint ->
            baseUri?.also { authorizationEndpoint.baseUri(baseUri) }
            authorizationRequestResolver?.also { authorizationEndpoint.authorizationRequestResolver(authorizationRequestResolver) }
            authorizationRequestRepository?.also { authorizationEndpoint.authorizationRequestRepository(authorizationRequestRepository) }
        }
    }
}
