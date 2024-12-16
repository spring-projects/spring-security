/*
 * Copyright 2002-2024 the original author or authors.
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
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter

/**
 * Configures [ServerHttpSecurity] using a [ServerHttpSecurity Kotlin DSL][ServerHttpSecurityDsl].
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
 *          authorizeExchange {
 *              authorize("/public", permitAll)
 *              authorize(anyExchange, authenticated)
 *          }
 *       }
 *   }
 * }
 * ```
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @param httpConfiguration the configurations to apply to [ServerHttpSecurity]
 */
operator fun ServerHttpSecurity.invoke(httpConfiguration: ServerHttpSecurityDsl.() -> Unit): SecurityWebFilterChain =
        ServerHttpSecurityDsl(this, httpConfiguration).build()

/**
 * A [ServerHttpSecurity] Kotlin DSL created by [`http { }`][invoke]
 * in order to configure [ServerHttpSecurity] using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @param init the configurations to apply to the provided [ServerHttpSecurity]
 * @property authenticationManager the default [ReactiveAuthenticationManager] to use
 */
@ServerSecurityMarker
class ServerHttpSecurityDsl(private val http: ServerHttpSecurity, private val init: ServerHttpSecurityDsl.() -> Unit) {

    var authenticationManager: ReactiveAuthenticationManager? = null
    var securityContextRepository: ServerSecurityContextRepository? = null

    /**
     * Allows configuring the [ServerHttpSecurity] to only be invoked when matching the
     * provided [ServerWebExchangeMatcher].
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
     *          securityMatcher(PathPatternParserServerWebExchangeMatcher("/api/&ast;&ast;"))
     *          formLogin {
     *              loginPage = "/log-in"
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param securityMatcher a [ServerWebExchangeMatcher] used to determine whether this
     * configuration should be invoked.
     */
    fun securityMatcher(securityMatcher: ServerWebExchangeMatcher) {
        this.http.securityMatcher(securityMatcher)
    }

    /**
     * Adds a [WebFilter] at a specific position.
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
     *          addFilterAt(CustomWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
     *       }
     *   }
     * }
     * ```
     *
     * @param webFilter the [WebFilter] to add
     * @param order the place to insert the [WebFilter]
     */
    fun addFilterAt(webFilter: WebFilter, order: SecurityWebFiltersOrder) {
        this.http.addFilterAt(webFilter, order)
    }

    /**
     * Adds a [WebFilter] before specific position.
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
     *          addFilterBefore(CustomWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
     *       }
     *   }
     * }
     * ```
     *
     * @param webFilter the [WebFilter] to add
     * @param order the place before which to insert the [WebFilter]
     */
    fun addFilterBefore(webFilter: WebFilter, order: SecurityWebFiltersOrder) {
        this.http.addFilterBefore(webFilter, order)
    }

    /**
     * Adds a [WebFilter] after specific position.
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
     *          addFilterAfter(CustomWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
     *       }
     *   }
     * }
     * ```
     *
     * @param webFilter the [WebFilter] to add
     * @param order the place after which to insert the [WebFilter]
     */
    fun addFilterAfter(webFilter: WebFilter, order: SecurityWebFiltersOrder) {
        this.http.addFilterAfter(webFilter, order)
    }

    /**
     * Enables form based authentication.
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
     *          formLogin {
     *              loginPage = "/log-in"
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param formLoginConfiguration custom configuration to apply to the form based
     * authentication
     * @see [ServerFormLoginDsl]
     */
    fun formLogin(formLoginConfiguration: ServerFormLoginDsl.() -> Unit) {
        val formLoginCustomizer = ServerFormLoginDsl().apply(formLoginConfiguration).get()
        this.http.formLogin(formLoginCustomizer)
    }

    /**
     * Allows restricting access based upon the [ServerWebExchange]
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
     *          authorizeExchange {
     *              authorize("/public", permitAll)
     *              authorize(anyExchange, authenticated)
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param authorizeExchangeConfiguration custom configuration that specifies
     * access for an exchange
     * @see [AuthorizeExchangeDsl]
     */
    fun authorizeExchange(authorizeExchangeConfiguration: AuthorizeExchangeDsl.() -> Unit) {
        val authorizeExchangeCustomizer = AuthorizeExchangeDsl().apply(authorizeExchangeConfiguration).get()
        this.http.authorizeExchange(authorizeExchangeCustomizer)
    }

    /**
     * Enables HTTP basic authentication.
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
     *          httpBasic { }
     *       }
     *   }
     * }
     * ```
     *
     * @param httpBasicConfiguration custom configuration to be applied to the
     * HTTP basic authentication
     * @see [ServerHttpBasicDsl]
     */
    fun httpBasic(httpBasicConfiguration: ServerHttpBasicDsl.() -> Unit) {
        val httpBasicCustomizer = ServerHttpBasicDsl().apply(httpBasicConfiguration).get()
        this.http.httpBasic(httpBasicCustomizer)
    }

    /**
     * Enables password management.
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
     *          passwordManagement {
     *              changePasswordPage = "/custom-change-password-page"
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param passwordManagementConfiguration custom configuration to be applied to the
     * password management
     * @see [ServerPasswordManagementDsl]
     * @since 5.6
     */
    fun passwordManagement(passwordManagementConfiguration: ServerPasswordManagementDsl.() -> Unit) {
        val passwordManagementCustomizer = ServerPasswordManagementDsl().apply(passwordManagementConfiguration).get()
        this.http.passwordManagement(passwordManagementCustomizer)
    }

    /**
     * Allows configuring response headers.
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
     *          headers {
     *              referrerPolicy {
     *                  policy = ReferrerPolicy.SAME_ORIGIN
     *              }
     *              frameOptions {
     *                  mode = Mode.DENY
     *              }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param headersConfiguration custom configuration to be applied to the
     * response headers
     * @see [ServerHeadersDsl]
     */
    fun headers(headersConfiguration: ServerHeadersDsl.() -> Unit) {
        val headersCustomizer = ServerHeadersDsl().apply(headersConfiguration).get()
        this.http.headers(headersCustomizer)
    }

    /**
     * Allows configuring CORS.
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
     *          cors {
     *              configurationSource = customConfigurationSource
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param corsConfiguration custom configuration to be applied to the
     * CORS headers
     * @see [ServerCorsDsl]
     */
    fun cors(corsConfiguration: ServerCorsDsl.() -> Unit) {
        val corsCustomizer = ServerCorsDsl().apply(corsConfiguration).get()
        this.http.cors(corsCustomizer)
    }

    /**
     * Allows configuring HTTPS redirection rules.
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
     *          redirectToHttps {
     *              httpsRedirectWhen {
     *                  it.request.headers.containsKey("X-Requires-Https")
     *              }
     *          }
     *      }
     *   }
     * }
     * ```
     *
     * @param httpsRedirectConfiguration custom configuration for the HTTPS redirect
     * rules.
     * @see [ServerHttpsRedirectDsl]
     */
    fun redirectToHttps(httpsRedirectConfiguration: ServerHttpsRedirectDsl.() -> Unit) {
        val httpsRedirectCustomizer = ServerHttpsRedirectDsl().apply(httpsRedirectConfiguration).get()
        this.http.redirectToHttps(httpsRedirectCustomizer)
    }

    /**
     * Allows configuring exception handling.
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
     *          exceptionHandling {
     *              authenticationEntryPoint = RedirectServerAuthenticationEntryPoint("/auth")
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param exceptionHandlingConfiguration custom configuration to apply to
     * exception handling
     * @see [ServerExceptionHandlingDsl]
     */
    fun exceptionHandling(exceptionHandlingConfiguration: ServerExceptionHandlingDsl.() -> Unit) {
        val exceptionHandlingCustomizer = ServerExceptionHandlingDsl().apply(exceptionHandlingConfiguration).get()
        this.http.exceptionHandling(exceptionHandlingCustomizer)
    }

    /**
     * Adds X509 based pre authentication to an application using a certificate provided by a client.
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
     *          x509 { }
     *       }
     *   }
     * }
     * ```
     *
     * @param x509Configuration custom configuration to apply to the X509 based pre authentication
     * @see [ServerX509Dsl]
     */
    fun x509(x509Configuration: ServerX509Dsl.() -> Unit) {
        val x509Customizer = ServerX509Dsl().apply(x509Configuration).get()
        this.http.x509(x509Customizer)
    }

    /**
     * Allows configuring request cache which is used when a flow is interrupted (i.e. due to requesting credentials)
     * so that the request can be replayed after authentication.
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
     *          requestCache { }
     *       }
     *   }
     * }
     * ```
     *
     * @param requestCacheConfiguration custom configuration to apply to the request cache
     * @see [ServerRequestCacheDsl]
     */
    fun requestCache(requestCacheConfiguration: ServerRequestCacheDsl.() -> Unit) {
        val requestCacheCustomizer = ServerRequestCacheDsl().apply(requestCacheConfiguration).get()
        this.http.requestCache(requestCacheCustomizer)
    }

    /**
     * Enables CSRF protection.
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
     *          csrf { }
     *       }
     *   }
     * }
     * ```
     *
     * @param csrfConfiguration custom configuration to apply to the CSRF protection
     * @see [ServerCsrfDsl]
     */
    fun csrf(csrfConfiguration: ServerCsrfDsl.() -> Unit) {
        val csrfCustomizer = ServerCsrfDsl().apply(csrfConfiguration).get()
        this.http.csrf(csrfCustomizer)
    }

    /**
     * Provides logout support.
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
     *          logout {
     *              logoutUrl = "/sign-out"
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param logoutConfiguration custom configuration to apply to logout
     * @see [ServerLogoutDsl]
     */
    fun logout(logoutConfiguration: ServerLogoutDsl.() -> Unit) {
        val logoutCustomizer = ServerLogoutDsl().apply(logoutConfiguration).get()
        this.http.logout(logoutCustomizer)
    }

    /**
     * Enables and configures anonymous authentication.
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
     *          anonymous {
     *              authorities = listOf(SimpleGrantedAuthority("ROLE_ANON"))
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param anonymousConfiguration custom configuration to apply to anonymous authentication
     * @see [ServerAnonymousDsl]
     */
    fun anonymous(anonymousConfiguration: ServerAnonymousDsl.() -> Unit) {
        val anonymousCustomizer = ServerAnonymousDsl().apply(anonymousConfiguration).get()
        this.http.anonymous(anonymousCustomizer)
    }

    /**
     * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0 Provider.
     * A [ReactiveClientRegistrationRepository] is required and must be registered as a Bean or
     * configured via [ServerOAuth2LoginDsl.clientRegistrationRepository].
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
     *          oauth2Login {
     *              clientRegistrationRepository = getClientRegistrationRepository()
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param oauth2LoginConfiguration custom configuration to configure the OAuth 2.0 Login
     * @see [ServerOAuth2LoginDsl]
     */
    fun oauth2Login(oauth2LoginConfiguration: ServerOAuth2LoginDsl.() -> Unit) {
        val oauth2LoginCustomizer = ServerOAuth2LoginDsl().apply(oauth2LoginConfiguration).get()
        this.http.oauth2Login(oauth2LoginCustomizer)
    }

    /**
     * Configures OAuth2 client support.
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
     *          oauth2Client {
     *              clientRegistrationRepository = getClientRegistrationRepository()
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param oauth2ClientConfiguration custom configuration to configure the OAuth 2.0 client
     * @see [ServerOAuth2ClientDsl]
     */
    fun oauth2Client(oauth2ClientConfiguration: ServerOAuth2ClientDsl.() -> Unit) {
        val oauth2ClientCustomizer = ServerOAuth2ClientDsl().apply(oauth2ClientConfiguration).get()
        this.http.oauth2Client(oauth2ClientCustomizer)
    }

    /**
     * Configures OAuth2 resource server support.
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
     *          oauth2ResourceServer {
     *              jwt { }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param oauth2ResourceServerConfiguration custom configuration to configure the OAuth 2.0 resource server
     * @see [ServerOAuth2ResourceServerDsl]
     */
    fun oauth2ResourceServer(oauth2ResourceServerConfiguration: ServerOAuth2ResourceServerDsl.() -> Unit) {
        val oauth2ResourceServerCustomizer = ServerOAuth2ResourceServerDsl().apply(oauth2ResourceServerConfiguration).get()
        this.http.oauth2ResourceServer(oauth2ResourceServerCustomizer)
    }

    /**
     * Configures logout support using an OpenID Connect 1.0 Provider.
     * A [ReactiveClientRegistrationRepository] is required and must be registered as a Bean or
     * configured via [ServerOidcLogoutDsl.clientRegistrationRepository].
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
     *              backChannel { }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param oidcLogoutConfiguration custom configuration to configure the OIDC 1.0 Logout
     * @see [ServerOidcLogoutDsl]
     */
    fun oidcLogout(oidcLogoutConfiguration: ServerOidcLogoutDsl.() -> Unit) {
        val oidcLogoutCustomizer = ServerOidcLogoutDsl().apply(oidcLogoutConfiguration).get()
        this.http.oidcLogout(oidcLogoutCustomizer)
    }

    /**
     * Configures Session Management support.
     *
     * Example:
     *
     * ```
     * @Configuration
     * @EnableWebFluxSecurity
     * open class SecurityConfig {
     *
     *  @Bean
     *  open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
     *      return http {
     *          sessionManagement {
     *              sessionConcurrency { }
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param sessionManagementConfig custom configuration to configure the Session Management
     * @since 6.3
     * @see [ServerSessionManagementDsl]
     */
    fun sessionManagement(sessionManagementConfig: ServerSessionManagementDsl.() -> Unit) {
        val sessionManagementCustomizer = ServerSessionManagementDsl().apply(sessionManagementConfig).get()
        this.http.sessionManagement(sessionManagementCustomizer)
    }

    /**
     * Configures One-Time Token Login support.
     *
     * Example:
     *
     * ```
     * @Configuration
     * @EnableWebFluxSecurity
     * open class SecurityConfig {
     *
     *  @Bean
     *  open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
     *      return http {
     *          oneTimeTokenLogin {
     *              tokenGenerationSuccessHandler = MyMagicLinkServerOneTimeTokenGenerationSuccessHandler()
     *          }
     *       }
     *   }
     * }
     * ```
     *
     * @param oneTimeTokenLoginConfiguration custom configuration to configure the One-Time Token Login
     * @since 6.4
     * @see [ServerOneTimeTokenLoginDsl]
     */
    fun oneTimeTokenLogin(oneTimeTokenLoginConfiguration: ServerOneTimeTokenLoginDsl.()-> Unit){
        val oneTimeTokenLoginCustomizer = ServerOneTimeTokenLoginDsl().apply(oneTimeTokenLoginConfiguration).get()
        this.http.oneTimeTokenLogin(oneTimeTokenLoginCustomizer)
    }

    /**
     * Apply all configurations to the provided [ServerHttpSecurity]
     */
    internal fun build(): SecurityWebFilterChain {
        init()
        authenticationManager?.also { this.http.authenticationManager(authenticationManager) }
        securityContextRepository?.also { this.http.securityContextRepository(securityContextRepository) }
        return this.http.build()
    }
}
