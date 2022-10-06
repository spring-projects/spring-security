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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.CrossOriginEmbedderPolicyServerHttpHeadersWriter
import org.springframework.security.web.server.header.CrossOriginOpenerPolicyServerHttpHeadersWriter
import org.springframework.security.web.server.header.CrossOriginResourcePolicyServerHttpHeadersWriter
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerHeadersDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerHeadersDslTests {
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
    fun `request when default headers configured then default headers are in the response`() {
        this.spring.register(DefaultHeadersConfig::class.java).autowire()

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
    open class DefaultHeadersConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers { }
            }
        }
    }

    @Test
    fun `request when headers disabled then no security headers are in the response`() {
        this.spring.register(HeadersDisabledConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().doesNotExist(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS)
                .expectHeader().doesNotExist(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS)
                .expectHeader().doesNotExist(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY)
                .expectHeader().doesNotExist(HttpHeaders.CACHE_CONTROL)
                .expectHeader().doesNotExist(HttpHeaders.EXPIRES)
                .expectHeader().doesNotExist(HttpHeaders.PRAGMA)
                .expectHeader().doesNotExist(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HeadersDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    disable()
                }
            }
        }
    }

    @Test
    fun `request when feature policy configured then feature policy header in response`() {
        this.spring.register(FeaturePolicyConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().valueEquals("Feature-Policy", "geolocation 'self'")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    @Suppress("DEPRECATION")
    open class FeaturePolicyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    featurePolicy("geolocation 'self'")
                }
            }
        }
    }

    @Test
    fun `request when no cross-origin policies configured then does not write cross-origin policies headers in response`() {
        this.spring.register(CrossOriginPoliciesConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().doesNotExist("Cross-Origin-Opener-Policy")
                .expectHeader().doesNotExist("Cross-Origin-Embedder-Policy")
                .expectHeader().doesNotExist("Cross-Origin-Resource-Policy")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CrossOriginPoliciesConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers { }
            }
        }
    }

    @Test
    fun `request when cross-origin custom policies configured then cross-origin custom policies headers in response`() {
        this.spring.register(CrossOriginPoliciesCustomConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().valueEquals("Cross-Origin-Opener-Policy", "same-origin")
                .expectHeader().valueEquals("Cross-Origin-Embedder-Policy", "require-corp")
                .expectHeader().valueEquals("Cross-Origin-Resource-Policy", "same-origin")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CrossOriginPoliciesCustomConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    crossOriginOpenerPolicy {
                        policy = CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN
                    }
                    crossOriginEmbedderPolicy {
                        policy = CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP
                    }
                    crossOriginResourcePolicy {
                        policy = CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy.SAME_ORIGIN
                    }
                }
            }
        }
    }
}
