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

import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerCsrfDsl]
 *
 * @author Eleftheria Stein
 */
class ServerCsrfDslTests {
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
    fun `post when CSRF protection enabled then requires CSRF token`() {
        this.spring.register(CsrfConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()
                .expectStatus().isForbidden
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CsrfConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf { }
            }
        }
    }

    @Test
    fun `post when CSRF protection disabled then CSRF token is not required`() {
        this.spring.register(CsrfDisabledConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()
                .expectStatus().isOk
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CsrfDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    disable()
                }
            }
        }

        @RestController
        internal class TestController {
            @PostMapping("/")
            fun home() {
            }
        }
    }

    @Test
    fun `post when request matches CSRF matcher then CSRF token required`() {
        this.spring.register(CsrfMatcherConfig::class.java).autowire()

        this.client.post()
                .uri("/csrf")
                .exchange()
                .expectStatus().isForbidden
    }

    @Test
    fun `post when request does not match CSRF matcher then CSRF token is not required`() {
        this.spring.register(CsrfMatcherConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()
                .expectStatus().isOk
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CsrfMatcherConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    requireCsrfProtectionMatcher = PathPatternParserServerWebExchangeMatcher("/csrf")
                }
            }
        }

        @RestController
        internal class TestController {
            @PostMapping("/")
            fun home() {
            }

            @PostMapping("/csrf")
            fun csrf() {
            }
        }
    }

    @Test
    fun `csrf when custom access denied handler then handler used`() {
        this.spring.register(CustomAccessDeniedHandlerConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()

        Mockito.verify<ServerAccessDeniedHandler>(CustomAccessDeniedHandlerConfig.ACCESS_DENIED_HANDLER)
                .handle(any(), any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAccessDeniedHandlerConfig {
        companion object {
            var ACCESS_DENIED_HANDLER: ServerAccessDeniedHandler = mock(ServerAccessDeniedHandler::class.java)
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    accessDeniedHandler = ACCESS_DENIED_HANDLER
                }
            }
        }
    }

    @Test
    fun `csrf when custom token repository then repository used`() {
        this.spring.register(CustomCsrfTokenRepositoryConfig::class.java).autowire()

        this.client.post()
                .uri("/")
                .exchange()

        Mockito.verify<ServerCsrfTokenRepository>(CustomCsrfTokenRepositoryConfig.TOKEN_REPOSITORY)
                .loadToken(any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomCsrfTokenRepositoryConfig {
        companion object {
            var TOKEN_REPOSITORY: ServerCsrfTokenRepository = mock(ServerCsrfTokenRepository::class.java)
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    csrfTokenRepository = TOKEN_REPOSITORY
                }
            }
        }
    }
}
