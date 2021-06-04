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

package org.springframework.security.config.web.servlet

import io.mockk.every
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
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [OAuth2ClientDsl]
 *
 * @author Eleftheria Stein
 */
class OAuth2ClientDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Client when custom client registration repository then bean is not required`() {
        this.spring.register(ClientRepoConfig::class.java).autowire()
    }

    @EnableWebSecurity
    open class ClientRepoConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                oauth2Client {
                    clientRegistrationRepository = InMemoryClientRegistrationRepository(
                            CommonOAuth2Provider.GOOGLE
                                    .getBuilder("google").clientId("clientId").clientSecret("clientSecret")
                                    .build()
                    )
                }
            }
        }
    }

    @Test
    fun `oauth2Client when custom authorized client repository then repository used`() {
        this.spring.register(ClientRepositoryConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(ClientRepositoryConfig.REQUEST_REPOSITORY)
        mockkObject(ClientRepositoryConfig.CLIENT)
        mockkObject(ClientRepositoryConfig.CLIENT_REPOSITORY)
        val authorizationRequest = OAuth2AuthorizationRequest
                .authorizationCode()
                .state("test")
                .clientId("clientId")
                .authorizationUri("https://test")
                .redirectUri("http://localhost/callback")
                .attributes(mapOf(Pair(OAuth2ParameterNames.REGISTRATION_ID, "registrationId")))
                .build()
        every {
            ClientRepositoryConfig.REQUEST_REPOSITORY.loadAuthorizationRequest(any())
        } returns authorizationRequest
        every {
            ClientRepositoryConfig.REQUEST_REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns authorizationRequest
        every {
            ClientRepositoryConfig.CLIENT.getTokenResponse(any())
        } returns OAuth2AccessTokenResponse
            .withToken("token")
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .build()
        every {
            ClientRepositoryConfig.CLIENT_REPOSITORY.saveAuthorizedClient(any(), any(), any(), any())
        } returns Unit

        this.mockMvc.get("/callback") {
            param("state", "test")
            param("code", "123")
        }

        verify(exactly = 1) { ClientRepositoryConfig.CLIENT_REPOSITORY.saveAuthorizedClient(any(), any(), any(), any()) }
    }

    @EnableWebSecurity
    open class ClientRepositoryConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val REQUEST_REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
            val CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
                OAuth2AccessTokenResponseClient {
                    OAuth2AccessTokenResponse.withToken("some tokenValue").build()
                }
            val CLIENT_REPOSITORY: OAuth2AuthorizedClientRepository = HttpSessionOAuth2AuthorizedClientRepository()
        }

        override fun configure(http: HttpSecurity) {
            http {
                oauth2Client {
                    authorizedClientRepository = CLIENT_REPOSITORY
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
}
