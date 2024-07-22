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

package org.springframework.security.config.web.server

import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] OIDC 1.0 login using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.2
 */
@ServerSecurityMarker
class ServerOidcLogoutDsl {
    var clientRegistrationRepository: ReactiveClientRegistrationRepository? = null
    var oidcSessionRegistry: ReactiveOidcSessionRegistry? = null

    private var backChannel: ((ServerHttpSecurity.OidcLogoutSpec.BackChannelLogoutConfigurer) -> Unit)? = null

    /**
     * Enables OIDC 1.0 Back-Channel Logout support.
     *
     * Example:
     *
     * ```
     * @Configuration
     * @EnableWebFluxSecurity
     * class SecurityConfig {
     *
     *  @Bean
     *  fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
     *      return http {
     *          oauth2Login { }
     *          oidcLogout {
     *              backChannel { 
     *                  sessionLogout { }
     *              }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param backChannelConfig custom configurations to configure OIDC 1.0 Back-Channel Logout support
     * @see [ServerOidcBackChannelLogoutDsl]
     */
    fun backChannel(backChannelConfig: ServerOidcBackChannelLogoutDsl.() -> Unit) {
        this.backChannel = ServerOidcBackChannelLogoutDsl().apply(backChannelConfig).get()
    }

    internal fun get(): (ServerHttpSecurity.OidcLogoutSpec) -> Unit {
        return { oidcLogout ->
            clientRegistrationRepository?.also { oidcLogout.clientRegistrationRepository(clientRegistrationRepository) }
            oidcSessionRegistry?.also { oidcLogout.oidcSessionRegistry(oidcSessionRegistry) }
            backChannel?.also { oidcLogout.backChannel(backChannel) }
        }
    }
}
