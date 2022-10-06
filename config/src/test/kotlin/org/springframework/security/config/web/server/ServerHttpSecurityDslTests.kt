/*
 * Copyright 2002-2021 the original author or authors.
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

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * Tests for [ServerHttpSecurityDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerHttpSecurityDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `request when it does not match the security matcher then the security rules do not apply`() {
        this.spring.register(PatternMatcherConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isNotFound
    }

    @Test
    fun `request when it matches the security matcher then the security rules apply`() {
        this.spring.register(PatternMatcherConfig::class.java).autowire()

        this.client.get()
                .uri("/api")
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PatternMatcherConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                securityMatcher(PathPatternParserServerWebExchangeMatcher("/api/**"))
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
            }
        }
    }

    @Test
    fun `post when default security configured then CSRF prevents the request`() {
        this.spring.register(DefaultSecurityConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()
                .expectStatus().isForbidden
    }

    @Test
    fun `request when default security configured then default headers are in the response`() {
        this.spring.register(DefaultSecurityConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff")
                .expectHeader().valueEquals(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name)
                .expectHeader().valueEquals(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains")
                .expectHeader().valueEquals(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate")
                .expectHeader().valueEquals(HttpHeaders.EXPIRES, "0")
                .expectHeader().valueEquals(HttpHeaders.PRAGMA, "no-cache")
                .expectHeader().valueEquals(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class DefaultSecurityConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
            }
        }
    }

    @Test
    fun `add filter at applies custom at specified filter position`() {
        this.spring.register(CustomWebFilterAtConfig::class.java).autowire()
        val filterChain = this.spring.context.getBean(SecurityWebFilterChain::class.java)
        val filters = filterChain.webFilters.collectList().block()

        assertThat(filters).last().isExactlyInstanceOf(CustomWebFilter::class.java)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomWebFilterAtConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                addFilterAt(CustomWebFilter(), SecurityWebFiltersOrder.LAST)
            }
        }
    }

    @Test
    fun `add filter before applies custom before specified filter position`() {
        this.spring.register(CustomWebFilterBeforeConfig::class.java).autowire()
        val filterChain = this.spring.context.getBean(SecurityWebFilterChain::class.java)
        val filters: List<Class<out WebFilter>>? = filterChain.webFilters.map { it.javaClass }.collectList().block()

        assertThat(filters).containsSubsequence(
                CustomWebFilter::class.java,
                SecurityContextServerWebExchangeWebFilter::class.java
        )
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomWebFilterBeforeConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                addFilterBefore(CustomWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
            }
        }
    }

    @Test
    fun `add filter after applies custom after specified filter position`() {
        this.spring.register(CustomWebFilterAfterConfig::class.java).autowire()
        val filterChain = this.spring.context.getBean(SecurityWebFilterChain::class.java)
        val filters: List<Class<out WebFilter>>? = filterChain.webFilters.map { it.javaClass }.collectList().block()

        assertThat(filters).containsSubsequence(
                SecurityContextServerWebExchangeWebFilter::class.java,
                CustomWebFilter::class.java
        )
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomWebFilterAfterConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                addFilterAfter(CustomWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
            }
        }
    }

    class CustomWebFilter : WebFilter {
        override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> = Mono.empty()
    }

    @Test
    fun `authentication manager when configured in DSL then used`() {
        this.spring.register(AuthenticationManagerConfig::class.java).autowire()
        mockkObject(AuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        every {
            AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any())
        } returns Mono.just(TestingAuthenticationToken("user", "password", "ROLE_USER"))
        this.client.get().uri("/").headers { headers ->
            headers.setBasicAuth("user", "password")
        }.exchange()
        verify(exactly = 1) { AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()) }
    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    open class AuthenticationManagerConfig {
        companion object {
            val AUTHENTICATION_MANAGER: ReactiveAuthenticationManager = NoopReactiveAuthenticationManager()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authenticationManager = AUTHENTICATION_MANAGER
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic { }
            }
        }
    }

    class NoopReactiveAuthenticationManager: ReactiveAuthenticationManager {
        override fun authenticate(authentication: Authentication?): Mono<Authentication> {
            return Mono.empty()
        }
    }
}
