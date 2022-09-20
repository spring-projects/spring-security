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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.IpAddressServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

/**
 * Tests for [ServerOAuth2LoginDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerOAuth2LoginDslTests {
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
    fun `oauth2Login when custom client registration repository then bean is not required`() {
        this.spring.register(ClientRepoConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class ClientRepoConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2Login {
                    clientRegistrationRepository = InMemoryReactiveClientRegistrationRepository(
                            CommonOAuth2Provider.GOOGLE
                                    .getBuilder("google").clientId("clientId").clientSecret("clientSecret")
                                    .build()
                    )
                }
            }
        }
    }

    @Test
    fun `login page when OAuth2 login configured then default login page created`() {
        this.spring.register(OAuth2LoginConfig::class.java, ClientConfig::class.java).autowire()

        this.client.get()
                .uri("/login")
                .exchange()
                .expectStatus().isOk
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class OAuth2LoginConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login { }
            }
        }
    }

    @Test
    fun `OAuth2 login when authorization request repository configured then custom repository used`() {
        this.spring.register(AuthorizationRequestRepositoryConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthorizationRequestRepositoryConfig.AUTHORIZATION_REQUEST_REPOSITORY)
        every {
            AuthorizationRequestRepositoryConfig.AUTHORIZATION_REQUEST_REPOSITORY.removeAuthorizationRequest(any())
        } returns Mono.empty()
        this.client.get()
                .uri("/login/oauth2/code/google")
                .exchange()

        verify(exactly = 1) { AuthorizationRequestRepositoryConfig.AUTHORIZATION_REQUEST_REPOSITORY.removeAuthorizationRequest(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthorizationRequestRepositoryConfig {

        companion object {
            val AUTHORIZATION_REQUEST_REPOSITORY: ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> = WebSessionOAuth2ServerAuthorizationRequestRepository()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login {
                    authorizationRequestRepository = AUTHORIZATION_REQUEST_REPOSITORY
                }
            }
        }
    }

    @Test
    fun `OAuth2 login when authorization redirect strategy configured then custom redirect strategy used`() {
        this.spring.register(AuthorizationRedirectStrategyConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthorizationRedirectStrategyConfig.AUTHORIZATION_REDIRECT_STRATEGY)
        every {
            AuthorizationRedirectStrategyConfig.AUTHORIZATION_REDIRECT_STRATEGY.sendRedirect(any(), any())
        } returns Mono.empty()
        this.client.get()
            .uri("/oauth2/authorization/google")
            .exchange()

        verify(exactly = 1) { AuthorizationRedirectStrategyConfig.AUTHORIZATION_REDIRECT_STRATEGY.sendRedirect(any(), any()) }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthorizationRedirectStrategyConfig {

        companion object {
            val AUTHORIZATION_REDIRECT_STRATEGY : ServerRedirectStrategy = DefaultServerRedirectStrategy()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login {
                    authorizationRedirectStrategy = AUTHORIZATION_REDIRECT_STRATEGY
                }
            }
        }
    }

    @Test
    fun `OAuth2 login when authentication matcher configured then custom matcher used`() {
        this.spring.register(AuthenticationMatcherConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthenticationMatcherConfig.AUTHENTICATION_MATCHER)
        every {
            AuthenticationMatcherConfig.AUTHENTICATION_MATCHER.matches(any())
        } returns Mono.empty()

        this.client.get()
                .uri("/")
                .exchange()

        verify(exactly = 1) { AuthenticationMatcherConfig.AUTHENTICATION_MATCHER.matches(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationMatcherConfig {

        companion object {
            val AUTHENTICATION_MATCHER: ServerWebExchangeMatcher = IpAddressServerWebExchangeMatcher("127.0.0.1")
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login {
                    authenticationMatcher = AUTHENTICATION_MATCHER
                }
            }
        }
    }

    @Test
    fun `OAuth2 login when authentication converter configured then custom converter used`() {
        this.spring.register(AuthenticationConverterConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthenticationConverterConfig.AUTHENTICATION_CONVERTER)
        every {
            AuthenticationConverterConfig.AUTHENTICATION_CONVERTER.convert(any())
        } returns Mono.empty()

        this.client.get()
                .uri("/login/oauth2/code/google")
                .exchange()

        verify(exactly = 1) { AuthenticationConverterConfig.AUTHENTICATION_CONVERTER.convert(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationConverterConfig {

        companion object {
            val AUTHENTICATION_CONVERTER: ServerAuthenticationConverter =
				ServerBearerTokenAuthenticationConverter()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login {
                    authenticationConverter = AUTHENTICATION_CONVERTER
                }
            }
        }
    }

    @Configuration
    open class ClientConfig {
        @Bean
        open fun clientRegistrationRepository(): ReactiveClientRegistrationRepository {
            return InMemoryReactiveClientRegistrationRepository(
                    CommonOAuth2Provider.GOOGLE
                            .getBuilder("google").clientId("clientId").clientSecret("clientSecret")
                            .build()
            )
        }
    }
}
