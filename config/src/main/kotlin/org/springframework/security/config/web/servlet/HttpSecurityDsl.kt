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

package org.springframework.security.config.web.servlet

import org.springframework.context.ApplicationContext
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.ClassUtils
import javax.servlet.Filter
import javax.servlet.http.HttpServletRequest

/**
 * Configures [HttpSecurity] using a [HttpSecurity Kotlin DSL][HttpSecurityDsl].
 *
 * Example:
 *
 * ```
 * @EnableWebSecurity
 * class SecurityConfig : WebSecurityConfigurerAdapter() {
 *
 *  override fun configure(http: HttpSecurity) {
 *      http {
 *          authorizeRequests {
 *              request("/public", permitAll)
 *              request(anyRequest, authenticated)
 *          }
 *          formLogin {
 *              loginPage = "/log-in"
 *          }
 *      }
 *  }
 * }
 * ```
 *
 * @author Eleftheria Stein
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
 */
@SecurityMarker
class HttpSecurityDsl(private val http: HttpSecurity, private val init: HttpSecurityDsl.() -> Unit) {
    private val HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector"

    /**
     * Allows configuring the [HttpSecurity] to only be invoked when matching the
     * provided pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not an the classpath, it will use an ant matcher.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          securityMatcher("/private/&ast;&ast;")
     *          formLogin {
     *              loginPage = "/log-in"
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param pattern one or more patterns used to determine whether this
     * configuration should be invoked.
     */
    fun securityMatcher(vararg pattern: String) {
        val mvcPresent = ClassUtils.isPresent(
                HANDLER_MAPPING_INTROSPECTOR,
                AuthorizeRequestsDsl::class.java.classLoader)
        this.http.requestMatchers {
            if (mvcPresent) {
                it.mvcMatchers(*pattern)
            } else {
                it.antMatchers(*pattern)
            }
        }
    }

    /**
     * Allows configuring the [HttpSecurity] to only be invoked when matching the
     * provided [RequestMatcher].
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          securityMatcher(AntPathRequestMatcher("/private/&ast;&ast;"))
     *          formLogin {
     *              loginPage = "/log-in"
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param requestMatcher one or more [RequestMatcher] used to determine whether
     * this configuration should be invoked.
     */
    fun securityMatcher(vararg requestMatcher: RequestMatcher) {
        this.http.requestMatchers {
            it.requestMatchers(*requestMatcher)
        }
    }

    /**
     * Enables form based authentication.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          formLogin {
     *              loginPage = "/log-in"
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          authorizeRequests {
     *              request("/public", permitAll)
     *              request(anyRequest, authenticated)
     *          }
     *      }
     *  }
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
     * Enables HTTP basic authentication.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          httpBasic {
     *              realmName = "Custom Realm"
     *          }
     *      }
     *  }
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
     * Allows configuring response headers.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          headers {
     *              referrerPolicy {
     *                  policy = ReferrerPolicy.SAME_ORIGIN
     *              }
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          cors {
     *              disable()
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          sessionManagement {
     *              invalidSessionUrl = "/invalid-session"
     *              sessionConcurrency {
     *                  maximumSessions = 1
     *              }
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          portMapper {
     *              map(80, 443)
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          requiresChannel {
     *              secure("/public", requiresInsecure)
     *              secure(anyRequest, requiresSecure)
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          x509 { }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          requestCache { }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          exceptionHandling {
     *              accessDeniedPage = "/access-denied"
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          csrf { }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          logout {
     *              logoutUrl = "/log-out"
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          saml2Login {
     *              relyingPartyRegistration = getSaml2RelyingPartyRegistration()
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          anonymous {
     *              authorities = listOf(SimpleGrantedAuthority("ROLE_ANON"))
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          oauth2Login {
     *              clientRegistrationRepository = getClientRegistrationRepository()
     *          }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          oauth2Client { }
     *      }
     *  }
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
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          oauth2ResourceServer {
     *              jwt { }
     *          }
     *      }
     *  }
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
     * Adds the [Filter] at the location of the specified [Filter] class.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      http {
     *          addFilterAt(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
     *      }
     *  }
     * }
     * ```
     *
     * @param filter the [Filter] to register
     * @param atFilter the location of another [Filter] that is already registered
     * (i.e. known) with Spring Security.
     */
    fun addFilterAt(filter: Filter, atFilter: Class<out Filter>) {
        this.http.addFilterAt(filter, atFilter)
    }

    /**
     * Apply all configurations to the provided [HttpSecurity]
     */
    internal fun build() {
        init()
    }
}
