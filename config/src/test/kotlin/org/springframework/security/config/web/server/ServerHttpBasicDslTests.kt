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
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono
import java.util.*

/**
 * Tests for [ServerHttpBasicDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerHttpBasicDslTests {
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
    fun `http basic when no authorization header then responds with unauthorized`() {
        this.spring.register(HttpBasicConfig::class.java, UserDetailsConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isUnauthorized
    }

    @Test
    fun `http basic when valid authorization header then responds with ok`() {
        this.spring.register(HttpBasicConfig::class.java, UserDetailsConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
                .exchange()
                .expectStatus().isOk
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class HttpBasicConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic { }
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
    fun `http basic when custom authentication manager then manager used`() {
        this.spring.register(CustomAuthenticationManagerConfig::class.java).autowire()
        mockkObject(CustomAuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        every {
            CustomAuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any())
        } returns Mono.just<Authentication>(TestingAuthenticationToken("user", "password", "ROLE_USER"))

        this.client.get()
                .uri("/")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
                .exchange()

        verify(exactly = 1) { CustomAuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAuthenticationManagerConfig {

        companion object {
            val AUTHENTICATION_MANAGER: ReactiveAuthenticationManager = NoopReactiveAuthenticationManager()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic {
                    authenticationManager = AUTHENTICATION_MANAGER
                }
            }
        }
    }

    class NoopReactiveAuthenticationManager: ReactiveAuthenticationManager {
        override fun authenticate(authentication: Authentication?): Mono<Authentication> {
            return Mono.empty()
        }
    }

    @Test
    fun `http basic when custom security context repository then repository used`() {
        this.spring.register(CustomSecurityContextRepositoryConfig::class.java, UserDetailsConfig::class.java).autowire()
        mockkObject(CustomSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPOSITORY)
        every {
            CustomSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPOSITORY.save(any(), any())
        } returns Mono.empty()

        this.client.get()
                .uri("/")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:password".toByteArray()))
                .exchange()

        verify(exactly = 1) { CustomSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPOSITORY.save(any(), any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomSecurityContextRepositoryConfig {

        companion object {
            val SECURITY_CONTEXT_REPOSITORY: ServerSecurityContextRepository = WebSessionServerSecurityContextRepository()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic {
                    securityContextRepository = SECURITY_CONTEXT_REPOSITORY
                }
            }
        }
    }

    @Test
    fun `http basic when custom authentication entry point then entry point used`() {
        this.spring.register(CustomAuthenticationEntryPointConfig::class.java, UserDetailsConfig::class.java).autowire()
        mockkObject(CustomAuthenticationEntryPointConfig.ENTRY_POINT)
        every {
            CustomAuthenticationEntryPointConfig.ENTRY_POINT.commence(any(), any())
        } returns Mono.empty()

        this.client.get()
                .uri("/")
                .exchange()

        verify(exactly = 1) { CustomAuthenticationEntryPointConfig.ENTRY_POINT.commence(any(), any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAuthenticationEntryPointConfig {

        companion object {
            val ENTRY_POINT: ServerAuthenticationEntryPoint = HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic {
                    authenticationEntryPoint = ENTRY_POINT
                }
            }
        }
    }

    @Test
    fun `http basic when custom authentication failure handler then failure handler used`() {
        this.spring.register(CustomAuthenticationFailureHandlerConfig::class.java, UserDetailsConfig::class.java).autowire()
        mockkObject(CustomAuthenticationFailureHandlerConfig.FAILURE_HANDLER)
        every {
            CustomAuthenticationFailureHandlerConfig.FAILURE_HANDLER.onAuthenticationFailure(any(), any())
        } returns Mono.empty()

        this.client.get()
            .uri("/")
            .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:wrong".toByteArray()))
            .exchange()

        verify(exactly = 1) { CustomAuthenticationFailureHandlerConfig.FAILURE_HANDLER.onAuthenticationFailure(any(), any()) }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomAuthenticationFailureHandlerConfig {

        companion object {
            val FAILURE_HANDLER: ServerAuthenticationFailureHandler = MockServerAuthenticationFailureHandler()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                httpBasic {
                    authenticationFailureHandler = FAILURE_HANDLER
                }
            }
        }
    }

    open class MockServerAuthenticationFailureHandler: ServerAuthenticationFailureHandler {
        override fun onAuthenticationFailure(
            webFilterExchange: WebFilterExchange?,
            exception: AuthenticationException?
        ): Mono<Void> {
            return Mono.empty()
        }

    }

    @Configuration
    open class UserDetailsConfig {
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
