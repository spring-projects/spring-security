/*
 * Copyright 2002-2022 the original author or authors.
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
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.security.web.server.csrf.CsrfToken
import org.springframework.security.web.server.csrf.DefaultCsrfToken
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.BodyInserters.fromMultipartData
import reactor.core.publisher.Mono

/**
 * Tests for [ServerCsrfDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerCsrfDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    private val token: CsrfToken = DefaultCsrfToken("csrf", "CSRF", "a")

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

    @Configuration
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

    @Configuration
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

    @Configuration
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
        mockkObject(CustomAccessDeniedHandlerConfig.ACCESS_DENIED_HANDLER)

        this.client.post()
                .uri("/")
                .exchange()

        verify(exactly = 1) { CustomAccessDeniedHandlerConfig.ACCESS_DENIED_HANDLER.handle(any(), any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAccessDeniedHandlerConfig {
        companion object {
            val ACCESS_DENIED_HANDLER: ServerAccessDeniedHandler = HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
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
        mockkObject(CustomCsrfTokenRepositoryConfig.TOKEN_REPOSITORY)
        every {
            CustomCsrfTokenRepositoryConfig.TOKEN_REPOSITORY.loadToken(any())
        } returns Mono.just(this.token)

        this.client.post()
                .uri("/")
                .exchange()

        verify(exactly = 1) { CustomCsrfTokenRepositoryConfig.TOKEN_REPOSITORY.loadToken(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomCsrfTokenRepositoryConfig {
        companion object {
            val TOKEN_REPOSITORY: ServerCsrfTokenRepository = WebSessionServerCsrfTokenRepository()
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

    @Test
    fun `csrf when multipart form data and not enabled then denied`() {
        this.spring.register(MultipartFormDataNotEnabledConfig::class.java).autowire()
        mockkObject(MultipartFormDataNotEnabledConfig.TOKEN_REPOSITORY)
        every {
            MultipartFormDataNotEnabledConfig.TOKEN_REPOSITORY.loadToken(any())
        } returns Mono.just(this.token)
        every {
            MultipartFormDataNotEnabledConfig.TOKEN_REPOSITORY.generateToken(any())
        } returns Mono.just(this.token)

        this.client.post()
                .uri("/")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(fromMultipartData(this.token.parameterName, this.token.token))
                .exchange()
                .expectStatus().isForbidden
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class MultipartFormDataNotEnabledConfig {
        companion object {
            val TOKEN_REPOSITORY: ServerCsrfTokenRepository = WebSessionServerCsrfTokenRepository()
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

    @Test
    fun `csrf when multipart form data and enabled then granted`() {
        this.spring.register(MultipartFormDataEnabledConfig::class.java).autowire()
        mockkObject(MultipartFormDataEnabledConfig.TOKEN_REPOSITORY)
        every {
            MultipartFormDataEnabledConfig.TOKEN_REPOSITORY.loadToken(any())
        } returns Mono.just(this.token)
        every {
            MultipartFormDataEnabledConfig.TOKEN_REPOSITORY.generateToken(any())
        } returns Mono.just(this.token)

        val csrfToken = createXorCsrfToken()
        this.client.post()
                .uri("/")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(fromMultipartData(csrfToken.parameterName, csrfToken.token))
                .exchange()
                .expectStatus().isOk
    }

    private fun createXorCsrfToken(): CsrfToken {
        val handler = XorServerCsrfTokenRequestAttributeHandler()
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"))
        handler.handle(exchange, Mono.just(this.token))
        val deferredCsrfToken: Mono<CsrfToken>? = exchange.getAttribute(CsrfToken::class.java.name)
        return deferredCsrfToken?.block()!!
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class MultipartFormDataEnabledConfig {
        companion object {
            val TOKEN_REPOSITORY: ServerCsrfTokenRepository = WebSessionServerCsrfTokenRepository()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    csrfTokenRepository = TOKEN_REPOSITORY
                    csrfTokenRequestHandler = XorServerCsrfTokenRequestAttributeHandler().apply {
                        setTokenFromMultipartDataEnabled(true)
                    }
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
    fun `csrf when custom request handler then handler used`() {
        this.spring.register(CustomRequestHandlerConfig::class.java).autowire()
        mockkObject(CustomRequestHandlerConfig.REPOSITORY)
        every {
            CustomRequestHandlerConfig.REPOSITORY.loadToken(any())
        } returns Mono.just(this.token)
        mockkObject(CustomRequestHandlerConfig.HANDLER)
        every {
            CustomRequestHandlerConfig.HANDLER.handle(any(), any())
        } returns Unit
        every {
            CustomRequestHandlerConfig.HANDLER.resolveCsrfTokenValue(any(), any())
        } returns Mono.just(this.token.token)

        this.client.post()
            .uri("/")
            .exchange()
            .expectStatus().isOk
        verify(exactly = 2) { CustomRequestHandlerConfig.REPOSITORY.loadToken(any()) }
        verify(exactly = 1) { CustomRequestHandlerConfig.HANDLER.resolveCsrfTokenValue(any(), any()) }
        verify(exactly = 1) { CustomRequestHandlerConfig.HANDLER.handle(any(), any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomRequestHandlerConfig {
        companion object {
            val REPOSITORY: ServerCsrfTokenRepository = WebSessionServerCsrfTokenRepository()
            val HANDLER: ServerCsrfTokenRequestHandler = ServerCsrfTokenRequestAttributeHandler()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                csrf {
                    csrfTokenRepository = REPOSITORY
                    csrfTokenRequestHandler = HANDLER
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
}
