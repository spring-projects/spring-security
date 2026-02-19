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

package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.*
import org.springframework.security.config.annotation.web.oauth2.server.authorization.OidcDsl
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 2.1 Authorization Server support using idiomatic Kotlin code.
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @property registeredClientRepository the repository of registered clients.
 * @property authorizationService the authorization service.
 * @property authorizationConsentService the authorization consent service.
 * @property authorizationServerSettings the authorization server settings.
 * @property tokenGenerator the token generator.
 */
@SecurityMarker
class OAuth2AuthorizationServerDsl {
    var registeredClientRepository: RegisteredClientRepository? = null
    var authorizationService: OAuth2AuthorizationService? = null
    var authorizationConsentService: OAuth2AuthorizationConsentService? = null
    var authorizationServerSettings: AuthorizationServerSettings? = null
    var tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>? = null

    private var clientAuthenticationConfig: ((OAuth2ClientAuthenticationConfigurer) -> Unit)? = null
    private var authorizationServerMetadataEndpointConfig: ((OAuth2AuthorizationServerMetadataEndpointConfigurer) -> Unit)? = null
    private var authorizationEndpointConfig: ((OAuth2AuthorizationEndpointConfigurer) -> Unit)? = null
    private var pushedAuthorizationRequestEndpointConfig: ((OAuth2PushedAuthorizationRequestEndpointConfigurer) -> Unit)? = null
    private var tokenEndpointConfig: ((OAuth2TokenEndpointConfigurer) -> Unit)? = null
    private var tokenIntrospectionEndpointConfig: ((OAuth2TokenIntrospectionEndpointConfigurer) -> Unit)? = null
    private var tokenRevocationEndpointConfig: ((OAuth2TokenRevocationEndpointConfigurer) -> Unit)? = null
    private var deviceAuthorizationEndpointConfig: ((OAuth2DeviceAuthorizationEndpointConfigurer) -> Unit)? = null
    private var deviceVerificationEndpointConfig: ((OAuth2DeviceVerificationEndpointConfigurer) -> Unit)? = null
    private var clientRegistrationEndpointConfig: ((OAuth2ClientRegistrationEndpointConfigurer) -> Unit)? = null
    private var oidcConfig: ((OidcConfigurer) -> Unit)? = null

    /**
     * Configures OAuth 2.0 Client Authentication.
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
     *             oauth2AuthorizationServer {
     *                 clientAuthentication {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param clientAuthenticationConfiguration custom configurations to configure OAuth 2.0 client authentication
     */
    fun clientAuthentication(clientAuthenticationConfiguration: OAuth2ClientAuthenticationConfigurer.() -> Unit) {
        this.clientAuthenticationConfig = clientAuthenticationConfiguration
    }

    /**
     * Configures the OAuth 2.0 Authorization Server Metadata Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 authorizationServerMetadataEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param authorizationServerMetadataEndpointConfiguration custom configurations to configure the metadata endpoint
     */
    fun authorizationServerMetadataEndpoint(authorizationServerMetadataEndpointConfiguration: OAuth2AuthorizationServerMetadataEndpointConfigurer.() -> Unit) {
        this.authorizationServerMetadataEndpointConfig = authorizationServerMetadataEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Authorization Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 authorizationEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param authorizationEndpointConfiguration custom configurations to configure the authorization endpoint
     */
    fun authorizationEndpoint(authorizationEndpointConfiguration: OAuth2AuthorizationEndpointConfigurer.() -> Unit) {
        this.authorizationEndpointConfig = authorizationEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Pushed Authorization Request Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 pushedAuthorizationRequestEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param pushedAuthorizationRequestEndpointConfiguration custom configurations to configure the PAR endpoint
     */
    fun pushedAuthorizationRequestEndpoint(pushedAuthorizationRequestEndpointConfiguration: OAuth2PushedAuthorizationRequestEndpointConfigurer.() -> Unit) {
        this.pushedAuthorizationRequestEndpointConfig = pushedAuthorizationRequestEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Token Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 tokenEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param tokenEndpointConfiguration custom configurations to configure the token endpoint
     */
    fun tokenEndpoint(tokenEndpointConfiguration: OAuth2TokenEndpointConfigurer.() -> Unit) {
        this.tokenEndpointConfig = tokenEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Token Introspection Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 tokenIntrospectionEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param tokenIntrospectionEndpointConfiguration custom configurations to configure the token introspection endpoint
     */
    fun tokenIntrospectionEndpoint(tokenIntrospectionEndpointConfiguration: OAuth2TokenIntrospectionEndpointConfigurer.() -> Unit) {
        this.tokenIntrospectionEndpointConfig = tokenIntrospectionEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Token Revocation Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 tokenRevocationEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param tokenRevocationEndpointConfiguration custom configurations to configure the token revocation endpoint
     */
    fun tokenRevocationEndpoint(tokenRevocationEndpointConfiguration: OAuth2TokenRevocationEndpointConfigurer.() -> Unit) {
        this.tokenRevocationEndpointConfig = tokenRevocationEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Device Authorization Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 deviceAuthorizationEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param deviceAuthorizationEndpointConfiguration custom configurations to configure the device authorization endpoint
     */
    fun deviceAuthorizationEndpoint(deviceAuthorizationEndpointConfiguration: OAuth2DeviceAuthorizationEndpointConfigurer.() -> Unit) {
        this.deviceAuthorizationEndpointConfig = deviceAuthorizationEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Device Verification Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 deviceVerificationEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param deviceVerificationEndpointConfiguration custom configurations to configure the device verification endpoint
     */
    fun deviceVerificationEndpoint(deviceVerificationEndpointConfiguration: OAuth2DeviceVerificationEndpointConfigurer.() -> Unit) {
        this.deviceVerificationEndpointConfig = deviceVerificationEndpointConfiguration
    }

    /**
     * Configures the OAuth 2.0 Dynamic Client Registration Endpoint.
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
     *             oauth2AuthorizationServer {
     *                 clientRegistrationEndpoint {
     *                     // custom configuration
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param clientRegistrationEndpointConfiguration custom configurations to configure the client registration endpoint
     */
    fun clientRegistrationEndpoint(clientRegistrationEndpointConfiguration: OAuth2ClientRegistrationEndpointConfigurer.() -> Unit) {
        this.clientRegistrationEndpointConfig = clientRegistrationEndpointConfiguration
    }

    /**
     * Configures OpenID Connect 1.0 support (disabled by default).
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
     *             oauth2AuthorizationServer {
     *                 oidc {
     *                     userInfoEndpoint {
     *                         userInfoMapper = myUserInfoMapper
     *                     }
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param oidcConfiguration custom configurations to configure OpenID Connect 1.0 support
     * @see [OidcDsl]
     */
    fun oidc(oidcConfiguration: OidcDsl.() -> Unit) {
        this.oidcConfig = OidcDsl().apply(oidcConfiguration).get()
    }

    internal fun get(): (OAuth2AuthorizationServerConfigurer) -> Unit {
        return { oauth2AuthorizationServer ->
            registeredClientRepository?.also { oauth2AuthorizationServer.registeredClientRepository(it) }
            authorizationService?.also { oauth2AuthorizationServer.authorizationService(it) }
            authorizationConsentService?.also { oauth2AuthorizationServer.authorizationConsentService(it) }
            authorizationServerSettings?.also { oauth2AuthorizationServer.authorizationServerSettings(it) }
            tokenGenerator?.also { oauth2AuthorizationServer.tokenGenerator(it) }
            clientAuthenticationConfig?.also { oauth2AuthorizationServer.clientAuthentication(it) }
            authorizationServerMetadataEndpointConfig?.also { oauth2AuthorizationServer.authorizationServerMetadataEndpoint(it) }
            authorizationEndpointConfig?.also { oauth2AuthorizationServer.authorizationEndpoint(it) }
            pushedAuthorizationRequestEndpointConfig?.also { oauth2AuthorizationServer.pushedAuthorizationRequestEndpoint(it) }
            tokenEndpointConfig?.also { oauth2AuthorizationServer.tokenEndpoint(it) }
            tokenIntrospectionEndpointConfig?.also { oauth2AuthorizationServer.tokenIntrospectionEndpoint(it) }
            tokenRevocationEndpointConfig?.also { oauth2AuthorizationServer.tokenRevocationEndpoint(it) }
            deviceAuthorizationEndpointConfig?.also { oauth2AuthorizationServer.deviceAuthorizationEndpoint(it) }
            deviceVerificationEndpointConfig?.also { oauth2AuthorizationServer.deviceVerificationEndpoint(it) }
            clientRegistrationEndpointConfig?.also { oauth2AuthorizationServer.clientRegistrationEndpoint(it) }
            oidcConfig?.also { oauth2AuthorizationServer.oidc(it) }
        }
    }
}

