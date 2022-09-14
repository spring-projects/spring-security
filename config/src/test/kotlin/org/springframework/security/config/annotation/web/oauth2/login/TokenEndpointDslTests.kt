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
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [TokenEndpointDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class TokenEndpointDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when custom access token response client then client used`() {
        this.spring.register(TokenConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(TokenConfig.REPOSITORY)
        mockkObject(TokenConfig.CLIENT)

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
        every {
            TokenConfig.REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns authorizationRequest
        every {
            TokenConfig.CLIENT.getTokenResponse(any())
        } returns OAuth2AccessTokenResponse
            .withToken("token")
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .build()

        this.mockMvc.get("/login/oauth2/code/google") {
            param("code", "auth-code")
            param("state", "test")
        }

        verify(exactly = 1) { TokenConfig.CLIENT.getTokenResponse(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class TokenConfig {

        companion object {
            val REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
            val CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
                DefaultAuthorizationCodeTokenResponseClient()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
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
            return http.build()
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
