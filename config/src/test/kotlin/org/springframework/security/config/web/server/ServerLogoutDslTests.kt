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
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

/**
 * Tests for [ServerLogoutDsl]
 *
 * @author Eleftheria Stein
 */
class ServerLogoutDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `logout when defaults used then redirects to login page`() {
        this.spring.register(LogoutConfig::class.java).autowire()

        val result = this.client
                .mutateWith(csrf())
                .post()
                .uri("/logout")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location)
                    .hasPath("/login")
                    .hasParameter("logout")
        }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class LogoutConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                logout { }
            }
        }
    }

    @Test
    fun `logout when custom logout URL then custom URL redirects to login page`() {
        this.spring.register(CustomUrlConfig::class.java).autowire()

        val result = this.client
                .mutateWith(csrf())
                .post()
                .uri("/custom-logout")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location)
                    .hasPath("/login")
                    .hasParameter("logout")
        }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomUrlConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                logout {
                    logoutUrl = "/custom-logout"
                }
            }
        }
    }

    @Test
    fun `logout when custom requires logout matcher then matching request redirects to login page`() {
        this.spring.register(RequiresLogoutConfig::class.java).autowire()

        val result = this.client
                .mutateWith(csrf())
                .post()
                .uri("/custom-logout")
                .exchange()
                .expectStatus().is3xxRedirection
                .returnResult(String::class.java)

        result.assertWithDiagnostics {
            assertThat(result.responseHeaders.location)
                    .hasPath("/login")
                    .hasParameter("logout")
        }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class RequiresLogoutConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                logout {
                    requiresLogout = PathPatternParserServerWebExchangeMatcher("/custom-logout")
                }
            }
        }
    }

    @Test
    fun `logout when custom logout handler then custom handler invoked`() {
        this.spring.register(CustomLogoutHandlerConfig::class.java).autowire()
        mockkObject(CustomLogoutHandlerConfig.LOGOUT_HANDLER)
        every { CustomLogoutHandlerConfig.LOGOUT_HANDLER.logout(any(), any()) } returns Mono.empty()

        this.client
                .mutateWith(csrf())
                .post()
                .uri("/logout")
                .exchange()

        verify(exactly = 1) { CustomLogoutHandlerConfig.LOGOUT_HANDLER.logout(any(), any()) }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomLogoutHandlerConfig {

        companion object {
            val LOGOUT_HANDLER: ServerLogoutHandler = ServerLogoutHandler { _, _ -> Mono.empty() }
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                logout {
                    logoutHandler = LOGOUT_HANDLER
                }
            }
        }
    }

    @Test
    fun `logout when custom logout success handler then custom handler invoked`() {
        this.spring.register(CustomLogoutSuccessHandlerConfig::class.java).autowire()
        mockkObject(CustomLogoutSuccessHandlerConfig.LOGOUT_HANDLER)
        every {
            CustomLogoutSuccessHandlerConfig.LOGOUT_HANDLER.onLogoutSuccess(any(), any())
        } returns Mono.empty()

        this.client
                .mutateWith(csrf())
                .post()
                .uri("/logout")
                .exchange()

        verify(exactly = 1) { CustomLogoutSuccessHandlerConfig.LOGOUT_HANDLER.onLogoutSuccess(any(), any()) }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomLogoutSuccessHandlerConfig {

        companion object {
            val LOGOUT_HANDLER: ServerLogoutSuccessHandler = ServerLogoutSuccessHandler { _, _ -> Mono.empty() }
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                logout {
                    logoutSuccessHandler = LOGOUT_HANDLER
                }
            }
        }
    }

    @Test
    fun `logout when disabled then logout URL not found`() {
        this.spring.register(LogoutDisabledConfig::class.java).autowire()

        this.client
                .mutateWith(csrf())
                .post()
                .uri("/logout")
                .exchange()
                .expectStatus().isNotFound
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class LogoutDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, permitAll)
                }
                logout {
                    disable()
                }
            }
        }
    }
}
