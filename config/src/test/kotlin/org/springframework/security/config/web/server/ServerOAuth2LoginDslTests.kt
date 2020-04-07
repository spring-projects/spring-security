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
import org.mockito.Mockito.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerOAuth2LoginDsl]
 *
 * @author Eleftheria Stein
 */
class ServerOAuth2LoginDslTests {
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
    fun `oauth2Login when custom client registration repository then bean is not required`() {
        this.spring.register(ClientRepoConfig::class.java).autowire()
    }

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

        this.client.get()
                .uri("/login/oauth2/code/google")
                .exchange()

        verify(AuthorizationRequestRepositoryConfig.AUTHORIZATION_REQUEST_REPOSITORY).removeAuthorizationRequest(any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthorizationRequestRepositoryConfig {
        companion object {
            var AUTHORIZATION_REQUEST_REPOSITORY = mock(ServerAuthorizationRequestRepository::class.java)
                    as ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>
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
    fun `OAuth2 login when authentication matcher configured then custom matcher used`() {
        this.spring.register(AuthenticationMatcherConfig::class.java, ClientConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()

        verify(AuthenticationMatcherConfig.AUTHENTICATION_MATCHER).matches(any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationMatcherConfig {
        companion object {
            var AUTHENTICATION_MATCHER: ServerWebExchangeMatcher = mock(ServerWebExchangeMatcher::class.java)
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

        this.client.get()
                .uri("/login/oauth2/code/google")
                .exchange()

        verify(AuthenticationConverterConfig.AUTHENTICATION_CONVERTER).convert(any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationConverterConfig {
        companion object {
            var AUTHENTICATION_CONVERTER: ServerAuthenticationConverter = mock(ServerAuthenticationConverter::class.java)
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
