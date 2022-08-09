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

package org.springframework.security.config.annotation.web.oauth2.login

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import jakarta.servlet.http.HttpServletRequest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [AuthorizationEndpointDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class AuthorizationEndpointDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when custom client registration repository then repository used`() {
        this.spring.register(ResolverConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(ResolverConfig.RESOLVER)
        every { ResolverConfig.RESOLVER.resolve(any()) }

        this.mockMvc.get("/oauth2/authorization/google")

        verify(exactly = 1) { ResolverConfig.RESOLVER.resolve(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class ResolverConfig {

        companion object {
            val RESOLVER: OAuth2AuthorizationRequestResolver = object : OAuth2AuthorizationRequestResolver {
                override fun resolve(
                    request: HttpServletRequest?
                ) = OAuth2AuthorizationRequest.authorizationCode().build()

                override fun resolve(
                    request: HttpServletRequest?, clientRegistrationId: String?
                ) = OAuth2AuthorizationRequest.authorizationCode().build()
            }
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestResolver = RESOLVER
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `oauth2Login when custom authorization request repository then repository used`() {
        this.spring.register(RequestRepoConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(RequestRepoConfig.REPOSITORY)
        every { RequestRepoConfig.REPOSITORY.saveAuthorizationRequest(any(), any(), any()) }

        this.mockMvc.get("/oauth2/authorization/google")

        verify(exactly = 1) { RequestRepoConfig.REPOSITORY.saveAuthorizationRequest(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class RequestRepoConfig {

        companion object {
            val REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `oauth2Login when custom authorization redirect strategy then redirect strategy used`() {
        this.spring.register(RedirectStrategyConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(RedirectStrategyConfig.REDIRECT_STRATEGY)
        every { RedirectStrategyConfig.REDIRECT_STRATEGY.sendRedirect(any(), any(), any()) }

        this.mockMvc.get("/oauth2/authorization/google")

        verify(exactly = 1) { RedirectStrategyConfig.REDIRECT_STRATEGY.sendRedirect(any(), any(), any()) }
    }

    @EnableWebSecurity
    open class RedirectStrategyConfig {

        companion object {
            val REDIRECT_STRATEGY: RedirectStrategy = DefaultRedirectStrategy()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRedirectStrategy = REDIRECT_STRATEGY
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `oauth2Login when custom authorization uri repository then uri used`() {
        this.spring.register(AuthorizationUriConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthorizationUriConfig.REPOSITORY)

        this.mockMvc.get("/connect/google")

        verify(exactly = 1) { AuthorizationUriConfig.REPOSITORY.saveAuthorizationRequest(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationUriConfig {

        companion object {
            val REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
                        baseUri = "/connect"
                    }
                }
            }
            return http.build()
        }
    }

    @Configuration
    open class ClientConfig {
        @Bean
        open fun clientRegistrationRepository(): ClientRegistrationRepository {
            return InMemoryClientRegistrationRepository(
                    CommonOAuth2Provider.GOOGLE
                            .getBuilder("google").clientId("clientId").clientSecret("clientSecret")
                            .build()
            )
        }
    }
}
