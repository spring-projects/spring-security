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

package org.springframework.security.config.web.servlet.oauth2.client

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [AuthorizationCodeGrantDsl]
 *
 * @author Eleftheria Stein
 */
class AuthorizationCodeGrantDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Client when custom authorization request repository then repository used`() {
        this.spring.register(RequestRepositoryConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(RequestRepositoryConfig.REQUEST_REPOSITORY)
        val authorizationRequest = getOAuth2AuthorizationRequest()
        every {
            RequestRepositoryConfig.REQUEST_REPOSITORY.loadAuthorizationRequest(any())
        } returns authorizationRequest
        every {
            RequestRepositoryConfig.REQUEST_REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns authorizationRequest

        this.mockMvc.get("/callback") {
            param("state", "test")
            param("code", "123")
        }

        verify(exactly = 1) { RequestRepositoryConfig.REQUEST_REPOSITORY.loadAuthorizationRequest(any()) }
    }

    @EnableWebSecurity
    open class RequestRepositoryConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val REQUEST_REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Client {
                    authorizationCodeGrant {
                        authorizationRequestRepository = REQUEST_REPOSITORY
                    }
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `oauth2Client when custom access token response client then client used`() {
        this.spring.register(AuthorizedClientConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(AuthorizedClientConfig.REQUEST_REPOSITORY)
        mockkObject(AuthorizedClientConfig.CLIENT)
        val authorizationRequest = getOAuth2AuthorizationRequest()
        every {
            AuthorizedClientConfig.REQUEST_REPOSITORY.loadAuthorizationRequest(any())
        } returns authorizationRequest
        every {
            AuthorizedClientConfig.REQUEST_REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns authorizationRequest
        every {
            AuthorizedClientConfig.CLIENT.getTokenResponse(any())
        } returns OAuth2AccessTokenResponse
            .withToken("token")
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .build()

        this.mockMvc.get("/callback") {
            param("state", "test")
            param("code", "123")
        }

        verify(exactly = 1) { AuthorizedClientConfig.CLIENT.getTokenResponse(any()) }
    }

    @EnableWebSecurity
    open class AuthorizedClientConfig : WebSecurityConfigurerAdapter() {
        companion object {
            val REQUEST_REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
            val CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
                OAuth2AccessTokenResponseClient {
                    OAuth2AccessTokenResponse.withToken("some tokenValue").build()
                }
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Client {
                    authorizationCodeGrant {
                        authorizationRequestRepository = REQUEST_REPOSITORY
                        accessTokenResponseClient = CLIENT
                    }
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `oauth2Client when custom authorization request resolver then request resolver used`() {
        this.spring.register(RequestResolverConfig::class.java, ClientConfig::class.java).autowire()
        val requestResolverConfig = this.spring.context.getBean(RequestResolverConfig::class.java)
        val authorizationRequest = getOAuth2AuthorizationRequest()
        every {
            requestResolverConfig.requestResolver.resolve(any())
        } returns authorizationRequest

        this.mockMvc.get("/callback") {
            param("state", "test")
            param("code", "123")
        }

        verify(exactly = 1) { requestResolverConfig.requestResolver.resolve(any()) }
    }

    @EnableWebSecurity
    open class RequestResolverConfig : WebSecurityConfigurerAdapter() {

        val requestResolver: OAuth2AuthorizationRequestResolver = mockk()

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Client {
                    authorizationCodeGrant {
                        authorizationRequestResolver = requestResolver
                    }
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
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
                            .getBuilder("google")
                            .registrationId("registrationId")
                            .clientId("clientId")
                            .clientSecret("clientSecret")
                            .build()
            )
        }
    }

    private fun getOAuth2AuthorizationRequest(): OAuth2AuthorizationRequest? {
        return OAuth2AuthorizationRequest
                .authorizationCode()
                .state("test")
                .clientId("clientId")
                .authorizationUri("https://test")
                .redirectUri("http://localhost/callback")
                .attributes(mapOf(Pair(OAuth2ParameterNames.REGISTRATION_ID, "registrationId")))
                .build()
    }
}
