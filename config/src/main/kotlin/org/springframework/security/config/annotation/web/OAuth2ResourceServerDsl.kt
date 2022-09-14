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

import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.oauth2.resourceserver.JwtDsl
import org.springframework.security.config.annotation.web.oauth2.resourceserver.OpaqueTokenDsl
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandler
import jakarta.servlet.http.HttpServletRequest

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 2.0 resource server support using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property accessDeniedHandler the [AccessDeniedHandler] to use for requests authenticating
 * with <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
 * @property authenticationEntryPoint the [AuthenticationEntryPoint] to use for requests authenticating
 * with <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
 * @property bearerTokenResolver the [BearerTokenResolver] to use for requests authenticating
 * with <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s.
 */
@SecurityMarker
class OAuth2ResourceServerDsl {
    var accessDeniedHandler: AccessDeniedHandler? = null
    var authenticationEntryPoint: AuthenticationEntryPoint? = null
    var bearerTokenResolver: BearerTokenResolver? = null
    var authenticationManagerResolver: AuthenticationManagerResolver<HttpServletRequest>? = null

    private var jwt: ((OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer) -> Unit)? = null
    private var opaqueToken: ((OAuth2ResourceServerConfigurer<HttpSecurity>.OpaqueTokenConfigurer) -> Unit)? = null

    /**
     * Enables JWT-encoded bearer token support.
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
     *             oauth2ResourceServer {
     *                 jwt {
     *                     jwkSetUri = "https://example.com/oauth2/jwk"
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param jwtConfig custom configurations to configure JWT resource server support
     * @see [JwtDsl]
     */
    fun jwt(jwtConfig: JwtDsl.() -> Unit) {
        this.jwt = JwtDsl().apply(jwtConfig).get()
    }

    /**
     * Enables opaque token support.
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
     *             oauth2ResourceServer {
     *                 opaqueToken { }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param opaqueTokenConfig custom configurations to configure opaque token resource server support
     * @see [OpaqueTokenDsl]
     */
    fun opaqueToken(opaqueTokenConfig: OpaqueTokenDsl.() -> Unit) {
        this.opaqueToken = OpaqueTokenDsl().apply(opaqueTokenConfig).get()
    }

    internal fun get(): (OAuth2ResourceServerConfigurer<HttpSecurity>) -> Unit {
        return { oauth2ResourceServer ->
            accessDeniedHandler?.also { oauth2ResourceServer.accessDeniedHandler(accessDeniedHandler) }
            authenticationEntryPoint?.also { oauth2ResourceServer.authenticationEntryPoint(authenticationEntryPoint) }
            bearerTokenResolver?.also { oauth2ResourceServer.bearerTokenResolver(bearerTokenResolver) }
            authenticationManagerResolver?.also { oauth2ResourceServer.authenticationManagerResolver(authenticationManagerResolver) }
            jwt?.also { oauth2ResourceServer.jwt(jwt) }
            opaqueToken?.also { oauth2ResourceServer.opaqueToken(opaqueToken) }
        }
    }
}
