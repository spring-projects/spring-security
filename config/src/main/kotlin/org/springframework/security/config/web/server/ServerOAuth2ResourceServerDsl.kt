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

import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.config.web.server.oauth2.resourceserver.ServerJwtDsl
import org.springframework.security.config.web.server.oauth2.resourceserver.ServerOpaqueTokenDsl
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.web.server.ServerWebExchange

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] OAuth 2.0 resource server using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property accessDeniedHandler the [ServerAccessDeniedHandler] to use for requests authenticating with
 * Bearer Tokens.
 * @property authenticationEntryPoint the [ServerAuthenticationEntryPoint] to use for requests authenticating with
 * Bearer Tokens.
 * @property bearerTokenConverter the [ServerAuthenticationConverter] to use for requests authenticating with
 * Bearer Tokens.
 * @property authenticationManagerResolver the [ReactiveAuthenticationManagerResolver] to use.
 */
class ServerOAuth2ResourceServerDsl {
    var accessDeniedHandler: ServerAccessDeniedHandler? = null
    var authenticationEntryPoint: ServerAuthenticationEntryPoint? = null
    var bearerTokenConverter: ServerAuthenticationConverter? = null
    var authenticationManagerResolver: ReactiveAuthenticationManagerResolver<ServerWebExchange>? = null

    private var jwt: ((ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec) -> Unit)? = null
    private var opaqueToken: ((ServerHttpSecurity.OAuth2ResourceServerSpec.OpaqueTokenSpec) -> Unit)? = null

    /**
     * Enables JWT-encoded bearer token support.
     *
     * Example:
     *
     * ```
     * @EnableWebFluxSecurity
     * class SecurityConfig {
     *
     *  @Bean
     *  fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
     *      return http {
     *          oauth2ResourceServer {
     *              jwt {
     *                  jwkSetUri = "https://example.com/oauth2/jwk"
     *              }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param jwtConfig custom configurations to configure JWT resource server support
     * @see [ServerJwtDsl]
     */
    fun jwt(jwtConfig: ServerJwtDsl.() -> Unit) {
        this.jwt = ServerJwtDsl().apply(jwtConfig).get()
    }

    /**
     * Enables opaque token support.
     *
     * Example:
     *
     * ```
     * @EnableWebFluxSecurity
     * class SecurityConfig {
     *
     *  @Bean
     *  fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
     *      return http {
     *          oauth2ResourceServer {
     *              opaqueToken {
     *                  introspectionUri = "https://example.com/introspect"
     *                  introspectionClientCredentials("client", "secret")
     *              }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param opaqueTokenConfig custom configurations to configure JWT resource server support
     * @see [ServerOpaqueTokenDsl]
     */
    fun opaqueToken(opaqueTokenConfig: ServerOpaqueTokenDsl.() -> Unit) {
        this.opaqueToken = ServerOpaqueTokenDsl().apply(opaqueTokenConfig).get()
    }

    internal fun get(): (ServerHttpSecurity.OAuth2ResourceServerSpec) -> Unit {
        return { oauth2ResourceServer ->
            accessDeniedHandler?.also { oauth2ResourceServer.accessDeniedHandler(accessDeniedHandler) }
            authenticationEntryPoint?.also { oauth2ResourceServer.authenticationEntryPoint(authenticationEntryPoint) }
            bearerTokenConverter?.also { oauth2ResourceServer.bearerTokenConverter(bearerTokenConverter) }
            authenticationManagerResolver?.also { oauth2ResourceServer.authenticationManagerResolver(authenticationManagerResolver!!) }
            jwt?.also { oauth2ResourceServer.jwt(jwt) }
            opaqueToken?.also { oauth2ResourceServer.opaqueToken(opaqueToken) }
        }
    }
}
