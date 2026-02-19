/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.oauth2.server.authorization

import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcProviderConfigurationEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcLogoutEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcClientRegistrationEndpointConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcUserInfoEndpointConfigurer

/**
 * A Kotlin DSL to configure OpenID Connect 1.0 support using idiomatic Kotlin code.
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 */
@OAuth2AuthorizationServerSecurityMarker
class OidcDsl {

    private var providerConfigurationEndpointConfig: ((OidcProviderConfigurationEndpointConfigurer) -> Unit)? = null
    private var logoutEndpointConfig: ((OidcLogoutEndpointConfigurer) -> Unit)? = null
    private var clientRegistrationEndpointConfig: ((OidcClientRegistrationEndpointConfigurer) -> Unit)? = null
    private var userInfoEndpointConfig: ((OidcUserInfoEndpointConfigurer) -> Unit)? = null

    /**
     * Configures the OpenID Connect 1.0 Provider Configuration Endpoint.
     *
     * @param providerConfigurationEndpointConfiguration custom configuration to apply
     */
    fun providerConfigurationEndpoint(providerConfigurationEndpointConfiguration: OidcProviderConfigurationEndpointDsl.() -> Unit) {
        this.providerConfigurationEndpointConfig = OidcProviderConfigurationEndpointDsl()
            .apply(providerConfigurationEndpointConfiguration).get()
    }

    /**
     * Configures the OpenID Connect 1.0 RP-Initiated Logout Endpoint.
     *
     * @param logoutEndpointConfiguration custom configuration to apply
     */
    fun logoutEndpoint(logoutEndpointConfiguration: OidcLogoutEndpointDsl.() -> Unit) {
        this.logoutEndpointConfig = OidcLogoutEndpointDsl()
            .apply(logoutEndpointConfiguration).get()
    }

    /**
     * Configures the OpenID Connect Dynamic Client Registration 1.0 Endpoint.
     *
     * @param clientRegistrationEndpointConfiguration custom configuration to apply
     */
    fun clientRegistrationEndpoint(clientRegistrationEndpointConfiguration: OidcClientRegistrationEndpointDsl.() -> Unit) {
        this.clientRegistrationEndpointConfig = OidcClientRegistrationEndpointDsl()
            .apply(clientRegistrationEndpointConfiguration).get()
    }

    /**
     * Configures the OpenID Connect 1.0 UserInfo Endpoint.
     *
     * @param userInfoEndpointConfiguration custom configuration to apply
     */
    fun userInfoEndpoint(userInfoEndpointConfiguration: OidcUserInfoEndpointDsl.() -> Unit) {
        this.userInfoEndpointConfig = OidcUserInfoEndpointDsl()
            .apply(userInfoEndpointConfiguration).get()
    }

    internal fun get(): (OidcConfigurer) -> Unit {
        return { oidc ->
            providerConfigurationEndpointConfig?.also { oidc.providerConfigurationEndpoint(it) }
            logoutEndpointConfig?.also { oidc.logoutEndpoint(it) }
            clientRegistrationEndpointConfig?.also { oidc.clientRegistrationEndpoint(it) }
            userInfoEndpointConfig?.also { oidc.userInfoEndpoint(it) }
        }
    }
}

