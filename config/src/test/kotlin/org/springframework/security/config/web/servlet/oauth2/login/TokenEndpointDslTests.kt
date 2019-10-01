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
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
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
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.util.*

/**
 * Tests for [TokenEndpointDsl]
 *
 * @author Eleftheria Stein
 */
class TokenEndpointDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when custom access token response client then client used`() {
        this.spring.register(TokenConfig::class.java, ClientConfig::class.java).autowire()

        val registrationId = "registrationId"
        val attributes = HashMap<String, Any>()
        attributes[OAuth2ParameterNames.REGISTRATION_ID] = registrationId
        val authorizationRequest = OAuth2AuthorizationRequest
                .authorizationCode()
                .state("test")
                .clientId("clientId")
                .authorizationUri("https://test")
                .redirectUri("http://localhost/login/oauth2/code/google")
                .attributes(attributes)
                .build()
        `when`(TokenConfig.REPOSITORY.removeAuthorizationRequest(any(), any()))
                .thenReturn(authorizationRequest)
        `when`(TokenConfig.CLIENT.getTokenResponse(any())).thenReturn(OAuth2AccessTokenResponse
                .withToken("token")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .build())

        this.mockMvc.get("/login/oauth2/code/google") {
            param("code", "auth-code")
            param("state", "test")
        }

        Mockito.verify(TokenConfig.CLIENT).getTokenResponse(any())
    }

    @EnableWebSecurity
    open class TokenConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> = mock(OAuth2AccessTokenResponseClient::class.java) as OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
            var REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> = mock(AuthorizationRequestRepository::class.java) as AuthorizationRequestRepository<OAuth2AuthorizationRequest>
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2Login {
                    tokenEndpoint {
                        accessTokenResponseClient = CLIENT
                    }
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
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
                            .getBuilder("google")
                            .registrationId("registrationId")
                            .clientId("clientId")
                            .clientSecret("clientSecret")
                            .build()
            )
        }
    }
}
