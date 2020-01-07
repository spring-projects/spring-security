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

package org.springframework.security.config.web.servlet.oauth2.login

import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito
import org.mockito.Mockito.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [AuthorizationEndpointDsl]
 *
 * @author Eleftheria Stein
 */
class AuthorizationEndpointDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when custom client registration repository then repository used`() {
        this.spring.register(ResolverConfig::class.java, ClientConfig::class.java).autowire()

        this.mockMvc.get("/oauth2/authorization/google")

        verify(ResolverConfig.RESOLVER).resolve(any())
    }

    @EnableWebSecurity
    open class ResolverConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var RESOLVER: OAuth2AuthorizationRequestResolver = Mockito.mock(OAuth2AuthorizationRequestResolver::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestResolver = RESOLVER
                    }
                }
            }
        }
    }

    @Test
    fun `oauth2Login when custom authorization request repository then repository used`() {
        this.spring.register(RequestRepoConfig::class.java, ClientConfig::class.java).autowire()

        this.mockMvc.get("/oauth2/authorization/google")

        verify(RequestRepoConfig.REPOSITORY).saveAuthorizationRequest(any(), any(), any())
    }

    @EnableWebSecurity
    open class RequestRepoConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> = Mockito.mock(AuthorizationRequestRepository::class.java) as AuthorizationRequestRepository<OAuth2AuthorizationRequest>
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
                    }
                }
            }
        }
    }

    @Test
    fun `oauth2Login when custom authorization uri repository then uri used`() {
        this.spring.register(AuthorizationUriConfig::class.java, ClientConfig::class.java).autowire()

        this.mockMvc.get("/connect/google")

        verify(AuthorizationUriConfig.REPOSITORY).saveAuthorizationRequest(any(), any(), any())
    }

    @EnableWebSecurity
    open class AuthorizationUriConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> = Mockito.mock(AuthorizationRequestRepository::class.java) as AuthorizationRequestRepository<OAuth2AuthorizationRequest>
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Login {
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
                        baseUri = "/connect"
                    }
                }
            }
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
