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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import java.util.Base64

/**
 * Tests for [AuthorizeExchangeDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class AuthorizeExchangeDslTests {
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
    fun `request when secured by matcher then responds with unauthorized`() {
        this.spring.register(MatcherAuthenticatedConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class MatcherAuthenticatedConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
            }
        }
    }

    @Test
    fun `request when allowed by matcher then responds with ok`() {
        this.spring.register(MatcherPermitAllConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isOk
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class MatcherPermitAllConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, permitAll)
                }
            }
        }

        @RestController
        internal class PathController {
            @RequestMapping("/")
            fun path() {
            }
        }
    }

    @Test
    fun `request when secured by pattern then responds with unauthorized`() {
        this.spring.register(PatternAuthenticatedConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Test
    fun `request when allowed by pattern then responds with ok`() {
        this.spring.register(PatternAuthenticatedConfig::class.java).autowire()

        this.client.get()
                .uri("/public")
                .exchange()
                .expectStatus().isOk
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PatternAuthenticatedConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize("/public", permitAll)
                    authorize("/**", authenticated)
                }
            }
        }

        @RestController
        internal class PathController {
            @RequestMapping("/public")
            fun public() {
            }
        }
    }

    @Test
    fun `request when missing required role then responds with forbidden`() {
        this.spring.register(HasRoleConfig::class.java).autowire()
        this.client
                .get()
                .uri("/")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
                .exchange()
                .expectStatus().isForbidden
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HasRoleConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, hasRole("ADMIN"))
                }
                httpBasic { }
            }
        }

        @Bean
        open fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                    .username("user")
                    .password("password")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(user)
        }
    }

    @Test
    fun `request when ip address does not match then responds with forbidden`() {
        this.spring.register(HasIpAddressConfig::class.java).autowire()

        this.client
            .get()
            .uri("/")
            .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
            .exchange()
            .expectStatus().isForbidden
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HasIpAddressConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, hasIpAddress("10.0.0.0/24"))
                }
                httpBasic { }
            }
        }

        @Bean
        open fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            return MapReactiveUserDetailsService(user)
        }
    }
}
