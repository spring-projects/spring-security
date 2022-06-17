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

import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] OAuth 2.0 login using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property authenticationManager the [ReactiveAuthenticationManager] used to determine if the provided
 * [Authentication] can be authenticated.
 * @property securityContextRepository the [ServerSecurityContextRepository] used to save the [Authentication].
 * @property authenticationSuccessHandler the [ServerAuthenticationSuccessHandler] used after authentication success.
 * @property authenticationFailureHandler the [ServerAuthenticationFailureHandler] used after authentication failure.
 * @property authenticationConverter the [ServerAuthenticationConverter] used for converting from a [ServerWebExchange]
 * to an [Authentication].
 * @property clientRegistrationRepository the repository of client registrations.
 * @property authorizedClientService the service responsible for associating an access token to a client and resource
 * owner.
 * @property authorizedClientRepository the repository for authorized client(s).
 * @property authorizationRequestRepository the repository to use for storing [OAuth2AuthorizationRequest]s.
 * @property authorizationRequestResolver the resolver used for resolving [OAuth2AuthorizationRequest]s.
 * @property authorizationRedirectStrategy the redirect strategy for Authorization Endpoint redirect URI.
 * @property authenticationMatcher the [ServerWebExchangeMatcher] used for determining if the request is an
 * authentication request.
 */
@ServerSecurityMarker
class ServerOAuth2LoginDsl {
    var authenticationManager: ReactiveAuthenticationManager? = null
    var securityContextRepository: ServerSecurityContextRepository? = null
    var authenticationSuccessHandler: ServerAuthenticationSuccessHandler? = null
    var authenticationFailureHandler: ServerAuthenticationFailureHandler? = null
    var authenticationConverter: ServerAuthenticationConverter? = null
    var clientRegistrationRepository: ReactiveClientRegistrationRepository? = null
    var authorizedClientService: ReactiveOAuth2AuthorizedClientService? = null
    var authorizedClientRepository: ServerOAuth2AuthorizedClientRepository? = null
    var authorizationRequestRepository: ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>? = null
    var authorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver? = null
    var authorizationRedirectStrategy: ServerRedirectStrategy? = null
    var authenticationMatcher: ServerWebExchangeMatcher? = null

    internal fun get(): (ServerHttpSecurity.OAuth2LoginSpec) -> Unit {
        return { oauth2Login ->
            authenticationManager?.also { oauth2Login.authenticationManager(authenticationManager) }
            securityContextRepository?.also { oauth2Login.securityContextRepository(securityContextRepository) }
            authenticationSuccessHandler?.also { oauth2Login.authenticationSuccessHandler(authenticationSuccessHandler) }
            authenticationFailureHandler?.also { oauth2Login.authenticationFailureHandler(authenticationFailureHandler) }
            authenticationConverter?.also { oauth2Login.authenticationConverter(authenticationConverter) }
            clientRegistrationRepository?.also { oauth2Login.clientRegistrationRepository(clientRegistrationRepository) }
            authorizedClientService?.also { oauth2Login.authorizedClientService(authorizedClientService) }
            authorizedClientRepository?.also { oauth2Login.authorizedClientRepository(authorizedClientRepository) }
            authorizationRequestRepository?.also { oauth2Login.authorizationRequestRepository(authorizationRequestRepository) }
            authorizationRequestResolver?.also { oauth2Login.authorizationRequestResolver(authorizationRequestResolver) }
            authorizationRedirectStrategy?.also { oauth2Login.authorizationRedirectStrategy(authorizationRedirectStrategy) }
            authenticationMatcher?.also { oauth2Login.authenticationMatcher(authenticationMatcher) }
        }
    }
}
