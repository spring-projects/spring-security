
/*
 * Copyright 2002-2023 the original author or authors.
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
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcLogoutConfigurer
import org.springframework.security.config.annotation.web.oauth2.login.OidcBackChannelLogoutDsl
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 1.0 Logout using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.2
 */
@SecurityMarker
class OidcLogoutDsl {
    var clientRegistrationRepository: ClientRegistrationRepository? = null
    var oidcSessionRegistry: OidcSessionRegistry? = null

    private var backChannel: ((OidcLogoutConfigurer<HttpSecurity>.BackChannelLogoutConfigurer) -> Unit)? = null

    /**
     * Configures the OIDC 1.0 Back-Channel endpoint.
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
     *             oauth2Login { }
     *             oidcLogout {
     *                 backChannel { }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param backChannelConfig custom configurations to configure the back-channel endpoint
     * @see [OidcBackChannelLogoutDsl]
     */
    fun backChannel(backChannelConfig: OidcBackChannelLogoutDsl.() -> Unit) {
        this.backChannel = OidcBackChannelLogoutDsl().apply(backChannelConfig).get()
    }

    internal fun get(): (OidcLogoutConfigurer<HttpSecurity>) -> Unit {
        return { oidcLogout ->
            clientRegistrationRepository?.also { oidcLogout.clientRegistrationRepository(clientRegistrationRepository) }
            oidcSessionRegistry?.also { oidcLogout.oidcSessionRegistry(oidcSessionRegistry) }
            backChannel?.also { oidcLogout.backChannel(backChannel) }
        }
    }

}
