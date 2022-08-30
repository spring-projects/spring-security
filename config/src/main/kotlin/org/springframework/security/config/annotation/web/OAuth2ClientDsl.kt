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

package org.springframework.security.config.annotation.web

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

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.oauth2.client.AuthorizationCodeGrantDsl
import org.springframework.security.config.annotation.web.oauth2.login.AuthorizationEndpointDsl
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 2.0 client support using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property clientRegistrationRepository the repository of client registrations.
 * @property authorizedClientRepository the repository for authorized client(s).
 * @property authorizedClientService the service for authorized client(s).
 */
@SecurityMarker
class OAuth2ClientDsl {
    var clientRegistrationRepository: ClientRegistrationRepository? = null
    var authorizedClientRepository: OAuth2AuthorizedClientRepository? = null
    var authorizedClientService: OAuth2AuthorizedClientService? = null

    private var authorizationCodeGrant: ((OAuth2ClientConfigurer<HttpSecurity>.AuthorizationCodeGrantConfigurer) -> Unit)? = null

    /**
     * Configures the OAuth 2.0 Authorization Code Grant.
     *
     * Example:
     *
     * ```
     * @Configuration
     * @EnableWebSecurity
     * class SecurityConfig {
     *
     *     @Bean
     *     fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
     *         http {
     *             oauth2Client {
     *                 authorizationCodeGrant {
     *                     authorizationRequestResolver = getAuthorizationRequestResolver()
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param authorizationCodeGrantConfig custom configurations to configure the authorization
     * code grant
     * @see [AuthorizationEndpointDsl]
     */
    fun authorizationCodeGrant(authorizationCodeGrantConfig: AuthorizationCodeGrantDsl.() -> Unit) {
        this.authorizationCodeGrant = AuthorizationCodeGrantDsl().apply(authorizationCodeGrantConfig).get()
    }

    internal fun get(): (OAuth2ClientConfigurer<HttpSecurity>) -> Unit {
        return { oauth2Client ->
            clientRegistrationRepository?.also { oauth2Client.clientRegistrationRepository(clientRegistrationRepository) }
            authorizedClientRepository?.also { oauth2Client.authorizedClientRepository(authorizedClientRepository) }
            authorizedClientService?.also { oauth2Client.authorizedClientService(authorizedClientService) }
            authorizationCodeGrant?.also { oauth2Client.authorizationCodeGrant(authorizationCodeGrant) }
        }
    }
}
