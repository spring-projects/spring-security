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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import java.util.*

/**
 * Tests for [ServerHttpsRedirectDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerHttpsRedirectDslTests {
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
    fun `request when matches redirect to HTTPS matcher then redirects to HTTPS`() {
        this.spring.register(HttpRedirectMatcherConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/secure")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location).hasScheme("https")
        }
    }

    @Test
    fun `request when does not match redirect to HTTPS matcher then does not redirect`() {
        this.spring.register(HttpRedirectMatcherConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isNotFound
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HttpRedirectMatcherConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                redirectToHttps {
                    httpsRedirectWhen(PathPatternParserServerWebExchangeMatcher("/secure"))
                }
            }
        }
    }

    @Test
    fun `request when matches redirect to HTTPS function then redirects to HTTPS`() {
        this.spring.register(HttpRedirectFunctionConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/")
                .header("X-Requires-Https", "required")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location).hasScheme("https")
        }
    }

    @Test
    fun `request when does not match redirect to HTTPS function then does not redirect`() {
        this.spring.register(HttpRedirectFunctionConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isNotFound
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HttpRedirectFunctionConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                redirectToHttps {
                    httpsRedirectWhen {
                        it.request.headers.containsKey("X-Requires-Https")
                    }
                }
            }
        }
    }

    @Test
    fun `request when multiple rules configured then only the last rule applies`() {
        this.spring.register(HttpRedirectMatcherAndFunctionConfig::class.java).autowire()

        this.client.get()
                .uri("/secure")
                .exchange()
                .expectStatus().isNotFound

        val result = this.client.get()
                .uri("/")
                .header("X-Requires-Https", "required")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location).hasScheme("https")
        }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HttpRedirectMatcherAndFunctionConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                redirectToHttps {
                    httpsRedirectWhen(PathPatternParserServerWebExchangeMatcher("/secure"))
                    httpsRedirectWhen {
                        it.request.headers.containsKey("X-Requires-Https")
                    }
                }
            }
        }
    }

    @Test
    fun `request when port mapper configured then redirected to HTTPS port`() {
        this.spring.register(PortMapperConfig::class.java).autowire()

        val result = this.client.get()
                .uri("http://localhost:543")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location).hasScheme("https").hasPort(123)
        }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PortMapperConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            val customPortMapper = PortMapperImpl()
            customPortMapper.setPortMappings(Collections.singletonMap("543", "123"))
            return http {
                redirectToHttps {
                    portMapper = customPortMapper
                }
            }
        }
    }
}
