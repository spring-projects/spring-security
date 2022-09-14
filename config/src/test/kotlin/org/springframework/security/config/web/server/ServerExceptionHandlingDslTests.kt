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

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import java.util.*

/**
 * Tests for [ServerExceptionHandlingDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerExceptionHandlingDslTests {
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
    fun `unauthenticated request when custom entry point then directed to custom entry point`() {
        this.spring.register(EntryPointConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            Assertions.assertThat(result.responseHeaders.location).hasPath("/auth")
        }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class EntryPointConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                exceptionHandling {
                    authenticationEntryPoint = RedirectServerAuthenticationEntryPoint("/auth")
                }
            }
        }
    }

    @Test
    fun `unauthorized request when custom access denied handler then directed to custom access denied handler`() {
        this.spring.register(AccessDeniedHandlerConfig::class.java).autowire()

        this.client
                .get()
                .uri("/")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
                .exchange()
                .expectStatus().isSeeOther
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AccessDeniedHandlerConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, hasRole("ADMIN"))
                }
                httpBasic { }
                exceptionHandling {
                    accessDeniedHandler = HttpStatusServerAccessDeniedHandler(HttpStatus.SEE_OTHER)
                }
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
