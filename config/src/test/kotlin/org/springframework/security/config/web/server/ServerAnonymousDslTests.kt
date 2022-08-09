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
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

/**
 * Tests for [ServerAnonymousDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerAnonymousDslTests {
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
    fun `authentication when anonymous enabled then is of type anonymous authentication`() {
        this.spring.register(AnonymousConfig::class.java, HttpMeController::class.java).autowire()

        this.client.get()
                .uri("/principal")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("anonymousUser")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AnonymousConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                anonymous { }
            }
        }
    }

    @Test
    fun `anonymous when custom principal specified then custom principal is used`() {
        this.spring.register(CustomPrincipalConfig::class.java, HttpMeController::class.java).autowire()

        this.client.get()
                .uri("/principal")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("anon")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomPrincipalConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                anonymous {
                    principal = "anon"
                }
            }
        }
    }

    @Test
    fun `anonymous when disabled then principal is null`() {
        this.spring.register(AnonymousDisabledConfig::class.java, HttpMeController::class.java).autowire()

        this.client.get()
                .uri("/principal")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().consumeWith { body -> assertThat(body.responseBody).isNull() }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AnonymousDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                anonymous {
                    disable()
                }
            }
        }
    }

    @Test
    fun `anonymous when custom key specified then custom key used`() {
        this.spring.register(CustomKeyConfig::class.java, HttpMeController::class.java).autowire()

        this.client.get()
                .uri("/key")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("key".hashCode().toString())
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomKeyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                anonymous {
                    key = "key"
                }
            }
        }
    }

    @Test
    fun `anonymous when custom authorities specified then custom authorities used`() {
        this.spring.register(CustomAuthoritiesConfig::class.java, HttpMeController::class.java).autowire()

        this.client.get()
                .uri("/principal")
                .exchange()
                .expectStatus().isOk
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAuthoritiesConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                anonymous {
                    authorities = listOf(SimpleGrantedAuthority("TEST"))
                }
                authorizeExchange {
                    authorize(anyExchange, hasAuthority("TEST"))
                }
            }
        }
    }

    @RestController
    class HttpMeController {
        @GetMapping("/principal")
        fun principal(@AuthenticationPrincipal principal: String?): String? {
            return principal
        }

        @GetMapping("/key")
        fun key(@AuthenticationPrincipal principal: Mono<AnonymousAuthenticationToken>): Mono<String> {
            return principal
                    .map { it.keyHash }
                    .map { it.toString() }
        }
    }
}
