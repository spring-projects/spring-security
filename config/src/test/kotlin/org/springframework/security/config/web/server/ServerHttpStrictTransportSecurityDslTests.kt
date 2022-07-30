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

package org.springframework.security.config.web.server.headers

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import java.time.Duration

/**
 * Tests for [ServerReferrerPolicyDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerHttpStrictTransportSecurityDslTests {
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
    fun `request when hsts configured then hsts header in response`() {
        this.spring.register(HstsConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HstsConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    hsts { }
                }
            }
        }
    }

    @Test
    fun `request when hsts disabled then no hsts header in response`() {
        this.spring.register(HstsDisabledConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().doesNotExist(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HstsDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    hsts {
                        disable()
                    }
                }
            }
        }
    }

    @Test
    fun `request when max age set then max age in response header`() {
        this.spring.register(MaxAgeConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=1 ; includeSubDomains")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class MaxAgeConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    hsts {
                        maxAge = Duration.ofSeconds(1)
                    }
                }
            }
        }
    }

    @Test
    fun `request when includeSubdomains false then includeSubdomains not in response header`() {
        this.spring.register(IncludeSubdomainsConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class IncludeSubdomainsConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    hsts {
                        includeSubdomains = false
                    }
                }
            }
        }
    }

    @Test
    fun `request when preload true then preload included in response header`() {
        this.spring.register(PreloadConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains ; preload")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PreloadConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    hsts {
                        preload = true
                    }
                }
            }
        }
    }
}
