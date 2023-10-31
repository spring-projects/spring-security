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

import org.springframework.context.ApplicationContext
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.ClassUtils
import jakarta.servlet.Filter
import jakarta.servlet.http.HttpServletRequest

/**
 * Configures [HttpSecurity] using a [HttpSecurity Kotlin DSL][HttpSecurityDsl].
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
 *             authorizeRequests {
 *                 authorize("/public", permitAll)
 *                 authorize(anyRequest, authenticated)
 *             }
 *             formLogin {
 *                 loginPage = "/log-in"
 *             }
 *         }
 *         return http.build()
 *     }
 * }
 * ```
 *
 * @author Eleftheria Stein
 * @author Norbert Nowak
 * @since 5.3
 * @param httpConfiguration the configurations to apply to [HttpSecurity]
 */
operator fun HttpSecurity.invoke(httpConfiguration: HttpSecurityDsl.() -> Unit) =
        HttpSecurityDsl(this, httpConfiguration).build()

/**
 * An [HttpSecurity] Kotlin DSL created by [`http { }`][invoke]
 * in order to configure [HttpSecurity] using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @param http the [HttpSecurity] which all configurations will be applied to
 * @param init the configurations to apply to the provided [HttpSecurity]
 * @property authenticationManager the default [AuthenticationManager] to use
 */
@SecurityMarker
class HttpSecurityDsl(private val http: HttpSecurity, private val init: HttpSecurityDsl.() -> Unit) {
    private val HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector"

    var authenticationManager: AuthenticationManager? = null

    /**
     * Applies a [SecurityConfigurerAdapter] to this [HttpSecurity]
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
     *             apply(CustomSecurityConfigurer<HttpSecurity>()) {
     *                 customProperty = "..."
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param configurer
     * the [SecurityConfigurerAdapter] for further customizations
     */
    fun <C : SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> apply(configurer: C, configuration: C.() -> Unit = { }): C {
        return this.http.apply(configurer).apply(configuration)
    }

    /**
     * Allows configuring the [HttpSecurity] to only be invoked when matching the
     * provided pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not an the classpath, it will use an ant matcher.
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
     *             securityMatcher("/private/&ast;&ast;")
     *             formLogin {
     *                 loginPage = "/log-in"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param pattern one or more patterns used to determine whether this
     * configuration should be invoked.
     */
    fun securityMatcher(vararg pattern: String) {
        this.http.securityMatchers {
            it.requestMatchers(*pattern)
        }
    }

    /**
     * Allows configuring the [HttpSecurity] to only be invoked when matching the
     * provided [RequestMatcher].
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
     *             securityMatcher(AntPathRequestMatcher("/private/&ast;&ast;"))
     *             formLogin {
     *                 loginPage = "/log-in"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param requestMatcher one or more [RequestMatcher] used to determine whether
     * this configuration should be invoked.
     */
    fun securityMatcher(vararg requestMatcher: RequestMatcher) {
        this.http.securityMatchers {
            it.requestMatchers(*requestMatcher)
        }
    }

    /**
     * Enables form based authentication.
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
     *             formLogin {
     *                 loginPage = "/log-in"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param formLoginConfiguration custom configurations to be applied
     * to the form based authentication
     * @see [FormLoginDsl]
     */
    fun formLogin(formLoginConfiguration: FormLoginDsl.() -> Unit) {
        val loginCustomizer = FormLoginDsl().apply(formLoginConfiguration).get()
        this.http.formLogin(loginCustomizer)
    }

    /**
     * Allows restricting access based upon the [HttpServletRequest]
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
     *             authorizeRequests {
     *                 authorize("/public", permitAll)
     *                 authorize(anyRequest, authenticated)
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param authorizeRequestsConfiguration custom configuration that specifies
     * access for requests
     * @see [AuthorizeRequestsDsl]
     */
    fun authorizeRequests(authorizeRequestsConfiguration: AuthorizeRequestsDsl.() -> Unit) {
        val authorizeRequestsCustomizer = AuthorizeRequestsDsl().apply(authorizeRequestsConfiguration).get()
        this.http.authorizeRequests(authorizeRequestsCustomizer)
    }

    /**
     * Allows restricting access based upon the [HttpServletRequest]
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
     *             authorizeHttpRequests {
     *                 authorize("/public", permitAll)
     *                 authorize(anyRequest, authenticated)
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param authorizeHttpRequestsConfiguration custom configuration that specifies
     * access for requests
     * @see [AuthorizeHttpRequestsDsl]
     * @since 5.7
     */
    fun authorizeHttpRequests(authorizeHttpRequestsConfiguration: AuthorizeHttpRequestsDsl.() -> Unit) {
        val authorizeHttpRequestsCustomizer = AuthorizeHttpRequestsDsl().apply(authorizeHttpRequestsConfiguration).get()
        this.http.authorizeHttpRequests(authorizeHttpRequestsCustomizer)
    }

    /**
     * Enables HTTP basic authentication.
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
     *             httpBasic {
     *                 realmName = "Custom Realm"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param httpBasicConfiguration custom configurations to be applied to the
     * HTTP basic authentication
     * @see [HttpBasicDsl]
     */
    fun httpBasic(httpBasicConfiguration: HttpBasicDsl.() -> Unit) {
        val httpBasicCustomizer = HttpBasicDsl().apply(httpBasicConfiguration).get()
        this.http.httpBasic(httpBasicCustomizer)
    }

    /**
     * Enables password management.
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
     *             passwordManagement {
     *                 changePasswordPage = "/custom-change-password-page"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param passwordManagementConfiguration custom configurations to be applied to the
     * password management
     * @see [PasswordManagementDsl]
     * @since 5.6
     */
    fun passwordManagement(passwordManagementConfiguration: PasswordManagementDsl.() -> Unit) {
        val passwordManagementCustomizer = PasswordManagementDsl().apply(passwordManagementConfiguration).get()
        this.http.passwordManagement(passwordManagementCustomizer)
    }

    /**
     * Allows configuring response headers.
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
     *             headers {
     *                 referrerPolicy {
     *                     policy = ReferrerPolicy.SAME_ORIGIN
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param headersConfiguration custom configurations to configure the
     * response headers
     * @see [HeadersDsl]
     */
    fun headers(headersConfiguration: HeadersDsl.() -> Unit) {
        val headersCustomizer = HeadersDsl().apply(headersConfiguration).get()
        this.http.headers(headersCustomizer)
    }

    /**
     * Enables CORS.
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
     *             cors {
     *                 disable()
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param corsConfiguration custom configurations to configure the
     * response headers
     * @see [CorsDsl]
     */
    fun cors(corsConfiguration: CorsDsl.() -> Unit) {
        val corsCustomizer = CorsDsl().apply(corsConfiguration).get()
        this.http.cors(corsCustomizer)
    }

    /**
     * Allows configuring session management.
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
     *             sessionManagement {
     *                 invalidSessionUrl = "/invalid-session"
     *                 sessionConcurrency {
     *                     maximumSessions = 1
     *                 }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param sessionManagementConfiguration custom configurations to configure
     * session management
     * @see [SessionManagementDsl]
     */
    fun sessionManagement(sessionManagementConfiguration: SessionManagementDsl.() -> Unit) {
        val sessionManagementCustomizer = SessionManagementDsl().apply(sessionManagementConfiguration).get()
        this.http.sessionManagement(sessionManagementCustomizer)
    }

    /**
     * Allows configuring a port mapper.
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
     *             portMapper {
     *                 map(80, 443)
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param portMapperConfiguration custom configurations to configure
     * the port mapper
     * @see [PortMapperDsl]
     */
    fun portMapper(portMapperConfiguration: PortMapperDsl.() -> Unit) {
        val portMapperCustomizer = PortMapperDsl().apply(portMapperConfiguration).get()
        this.http.portMapper(portMapperCustomizer)
    }

    /**
     * Allows configuring channel security based upon the [HttpServletRequest]
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
     *             requiresChannel {
     *                 secure("/public", requiresInsecure)
     *                 secure(anyRequest, requiresSecure)
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param requiresChannelConfiguration custom configuration that specifies
     * channel security
     * @see [RequiresChannelDsl]
     */
    fun requiresChannel(requiresChannelConfiguration: RequiresChannelDsl.() -> Unit) {
        val requiresChannelCustomizer = RequiresChannelDsl().apply(requiresChannelConfiguration).get()
        this.http.requiresChannel(requiresChannelCustomizer)
    }

    /**
     * Adds X509 based pre authentication to an application
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
     *             x509 { }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param x509Configuration custom configuration to apply to the
     * X509 based pre authentication
     * @see [X509Dsl]
     */
    fun x509(x509Configuration: X509Dsl.() -> Unit) {
        val x509Customizer = X509Dsl().apply(x509Configuration).get()
        this.http.x509(x509Customizer)
    }

    /**
     * Enables request caching. Specifically this ensures that requests that
     * are saved (i.e. after authentication is required) are later replayed.
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
     *             requestCache { }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param requestCacheConfiguration custom configuration to apply to the
     * request cache
     * @see [RequestCacheDsl]
     */
    fun requestCache(requestCacheConfiguration: RequestCacheDsl.() -> Unit) {
        val requestCacheCustomizer = RequestCacheDsl().apply(requestCacheConfiguration).get()
        this.http.requestCache(requestCacheCustomizer)
    }

    /**
     * Allows configuring exception handling.
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
     *             exceptionHandling {
     *                 accessDeniedPage = "/access-denied"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param exceptionHandlingConfiguration custom configuration to apply to the
     * exception handling
     * @see [ExceptionHandlingDsl]
     */
    fun exceptionHandling(exceptionHandlingConfiguration: ExceptionHandlingDsl.() -> Unit) {
        val exceptionHandlingCustomizer = ExceptionHandlingDsl().apply(exceptionHandlingConfiguration).get()
        this.http.exceptionHandling(exceptionHandlingCustomizer)
    }

    /**
     * Enables CSRF protection.
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
     *             csrf { }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param csrfConfiguration custom configuration to apply to CSRF
     * @see [CsrfDsl]
     */
    fun csrf(csrfConfiguration: CsrfDsl.() -> Unit) {
        val csrfCustomizer = CsrfDsl().apply(csrfConfiguration).get()
        this.http.csrf(csrfCustomizer)
    }

    /**
     * Provides logout support.
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
     *             logout {
     *                 logoutUrl = "/log-out"
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param logoutConfiguration custom configuration to apply to logout
     * @see [LogoutDsl]
     */
    fun logout(logoutConfiguration: LogoutDsl.() -> Unit) {
        val logoutCustomizer = LogoutDsl().apply(logoutConfiguration).get()
        this.http.logout(logoutCustomizer)
    }

    /**
     * Configures authentication support using a SAML 2.0 Service Provider.
     * A [RelyingPartyRegistrationRepository] is required and must be registered with
     * the [ApplicationContext] or configured via
     * [Saml2Dsl.relyingPartyRegistrationRepository]
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
     *             saml2Login {
     *                 relyingPartyRegistration = getSaml2RelyingPartyRegistration()
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param saml2LoginConfiguration custom configuration to configure the
     * SAML2 service provider
     * @see [Saml2Dsl]
     */
    fun saml2Login(saml2LoginConfiguration: Saml2Dsl.() -> Unit) {
        val saml2LoginCustomizer = Saml2Dsl().apply(saml2LoginConfiguration).get()
        this.http.saml2Login(saml2LoginCustomizer)
    }

    /**
     * Allows configuring how an anonymous user is represented.
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
     *             anonymous {
     *                 authorities = listOf(SimpleGrantedAuthority("ROLE_ANON"))
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param anonymousConfiguration custom configuration to configure the
     * anonymous user
     * @see [AnonymousDsl]
     */
    fun anonymous(anonymousConfiguration: AnonymousDsl.() -> Unit) {
        val anonymousCustomizer = AnonymousDsl().apply(anonymousConfiguration).get()
        this.http.anonymous(anonymousCustomizer)
    }

    /**
     * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0 Provider.
     * A [ClientRegistrationRepository] is required and must be registered as a Bean or
     * configured via [OAuth2LoginDsl.clientRegistrationRepository]
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
     *             oauth2Login {
     *                 clientRegistrationRepository = getClientRegistrationRepository()
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param oauth2LoginConfiguration custom configuration to configure the
     * OAuth 2.0 Login
     * @see [OAuth2LoginDsl]
     */
    fun oauth2Login(oauth2LoginConfiguration: OAuth2LoginDsl.() -> Unit) {
        val oauth2LoginCustomizer = OAuth2LoginDsl().apply(oauth2LoginConfiguration).get()
        this.http.oauth2Login(oauth2LoginCustomizer)
    }

    /**
     * Configures OAuth 2.0 client support.
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
     *             oauth2Client { }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param oauth2ClientConfiguration custom configuration to configure the
     * OAuth 2.0 client support
     * @see [OAuth2ClientDsl]
     */
    fun oauth2Client(oauth2ClientConfiguration: OAuth2ClientDsl.() -> Unit) {
        val oauth2ClientCustomizer = OAuth2ClientDsl().apply(oauth2ClientConfiguration).get()
        this.http.oauth2Client(oauth2ClientCustomizer)
    }

    /**
     * Configures OAuth 2.0 resource server support.
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
     *                 jwt { }
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param oauth2ResourceServerConfiguration custom configuration to configure the
     * OAuth 2.0 resource server support
     * @see [OAuth2ResourceServerDsl]
     */
    fun oauth2ResourceServer(oauth2ResourceServerConfiguration: OAuth2ResourceServerDsl.() -> Unit) {
        val oauth2ResourceServerCustomizer = OAuth2ResourceServerDsl().apply(oauth2ResourceServerConfiguration).get()
        this.http.oauth2ResourceServer(oauth2ResourceServerCustomizer)
    }

    /**
     * Configures Remember Me authentication.
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
     *             rememberMe {
     *                 tokenValiditySeconds = 604800
     *             }
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param rememberMeConfiguration custom configuration to configure remember me
     * @see [RememberMeDsl]
     */
    fun rememberMe(rememberMeConfiguration: RememberMeDsl.() -> Unit) {
        val rememberMeCustomizer = RememberMeDsl().apply(rememberMeConfiguration).get()
        this.http.rememberMe(rememberMeCustomizer)
    }

    /**
     * Adds the [Filter] at the location of the specified [Filter] class.
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
     *             addFilterAt(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param atFilter the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Deprecated("Use 'addFilterAt<T>(filter)' instead.")
    fun addFilterAt(filter: Filter, atFilter: Class<out Filter>) {
        this.http.addFilterAt(filter, atFilter)
    }

    /**
     * Adds the [Filter] at the location of the specified [Filter] class.
     * Variant that is leveraging Kotlin reified type parameters.
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
     *             addFilterAt<UsernamePasswordAuthenticationFilter>(CustomFilter())
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param T the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Suppress("DEPRECATION")
    inline fun <reified T: Filter> addFilterAt(filter: Filter) {
        this.addFilterAt(filter, T::class.java)
    }

    /**
     * Adds the [Filter] after the location of the specified [Filter] class.
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
     *             addFilterAfter(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param afterFilter the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Deprecated("Use 'addFilterAfter<T>(filter)' instead.")
    fun addFilterAfter(filter: Filter, afterFilter: Class<out Filter>) {
        this.http.addFilterAfter(filter, afterFilter)
    }

    /**
     * Adds the [Filter] after the location of the specified [Filter] class.
     * Variant that is leveraging Kotlin reified type parameters.
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
     *             addFilterAfter<UsernamePasswordAuthenticationFilter>(CustomFilter())
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param T the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Suppress("DEPRECATION")
    inline fun <reified T: Filter> addFilterAfter(filter: Filter) {
        this.addFilterAfter(filter, T::class.java)
    }

    /**
     * Adds the [Filter] before the location of the specified [Filter] class.
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
     *             addFilterBefore(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param beforeFilter the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Deprecated("Use 'addFilterBefore<T>(filter)' instead.")
    fun addFilterBefore(filter: Filter, beforeFilter: Class<out Filter>) {
        this.http.addFilterBefore(filter, beforeFilter)
    }

    /**
     * Adds the [Filter] before the location of the specified [Filter] class.
     * Variant that is leveraging Kotlin reified type parameters.
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
     *             addFilterBefore<UsernamePasswordAuthenticationFilter>(CustomFilter())
     *         }
     *         return http.build()
     *     }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param T the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    @Suppress("DEPRECATION")
    inline fun <reified T: Filter> addFilterBefore(filter: Filter) {
        this.addFilterBefore(filter, T::class.java)
    }

    /**
     * Apply all configurations to the provided [HttpSecurity]
     */
    internal fun build() {
        init()
        authenticationManager?.also { this.http.authenticationManager(authenticationManager) }
    }

    /**
     * Enables security context configuration.
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
     *        http {
     *           securityContext {
     *               securityContextRepository = SECURITY_CONTEXT_REPOSITORY
     *           }
     *        }
     *        return http.build()
     *     }
     * }
     * ```
     * @author Norbert Nowak
     * @since 5.7
     * @param securityContextConfiguration configuration to be applied to Security Context
     * @see [SecurityContextDsl]
     */
    fun securityContext(securityContextConfiguration: SecurityContextDsl.() -> Unit) {
        val securityContextCustomizer = SecurityContextDsl().apply(securityContextConfiguration).get()
        this.http.securityContext(securityContextCustomizer)
    }
}
