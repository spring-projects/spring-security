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

package org.springframework.security.config.web.servlet

import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.*
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
        val authorizationRequest = OAuth2AuthorizationRequest
                .authorizationCode()
                .state("test")
                .clientId("clientId")
                .authorizationUri("https://test")
                .redirectUri("http://localhost/callback")
                .attributes(mapOf(Pair(OAuth2ParameterNames.REGISTRATION_ID, "registrationId")))
                .build()
        `when`(ClientRepositoryConfig.REQUEST_REPOSITORY.loadAuthorizationRequest(any()))
                .thenReturn(authorizationRequest)
        `when`(ClientRepositoryConfig.REQUEST_REPOSITORY.removeAuthorizationRequest(any(), any()))
                .thenReturn(authorizationRequest)
        `when`(ClientRepositoryConfig.CLIENT.getTokenResponse(any()))
                .thenReturn(OAuth2AccessTokenResponse
                        .withToken("token")
                        .tokenType(OAuth2AccessToken.TokenType.BEARER)
                        .build())

        this.mockMvc.get("/callback") {
            param("state", "test")
            param("code", "123")
        }

        verify(ClientRepositoryConfig.CLIENT_REPOSITORY).saveAuthorizedClient(any(), any(), any(), any())
    }

    @EnableWebSecurity
    open class ClientRepositoryConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var REQUEST_REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> = mock(AuthorizationRequestRepository::class.java) as AuthorizationRequestRepository<OAuth2AuthorizationRequest>
            var CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> = mock(OAuth2AccessTokenResponseClient::class.java) as OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
            var CLIENT_REPOSITORY: OAuth2AuthorizedClientRepository = mock(OAuth2AuthorizedClientRepository::class.java)
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
