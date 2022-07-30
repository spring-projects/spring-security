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
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [RedirectionEndpointDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class RedirectionEndpointDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when redirection endpoint configured then custom redirection endpoing used`() {
        this.spring.register(UserServiceConfig::class.java, ClientConfig::class.java).autowire()
        mockkObject(UserServiceConfig.REPOSITORY)
        mockkObject(UserServiceConfig.CLIENT)
        mockkObject(UserServiceConfig.USER_SERVICE)

        val registrationId = "registrationId"
        val attributes = HashMap<String, Any>()
        attributes[OAuth2ParameterNames.REGISTRATION_ID] = registrationId
        val authorizationRequest = OAuth2AuthorizationRequest
                .authorizationCode()
                .state("test")
                .clientId("clientId")
                .authorizationUri("https://test")
                .redirectUri("http://localhost/callback")
                .attributes(attributes)
                .build()
        every {
            UserServiceConfig.REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns authorizationRequest
        every {
            UserServiceConfig.CLIENT.getTokenResponse(any())
        } returns OAuth2AccessTokenResponse
            .withToken("token")
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .build()
        every {
            UserServiceConfig.USER_SERVICE.loadUser(any())
        } returns DefaultOAuth2User(listOf(SimpleGrantedAuthority("ROLE_USER")), mapOf(Pair("user", "user")), "user")

        this.mockMvc.get("/callback") {
            param("code", "auth-code")
            param("state", "test")
        }.andExpect {
            redirectedUrl("/")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class UserServiceConfig {

        companion object {
            val REPOSITORY: AuthorizationRequestRepository<OAuth2AuthorizationRequest> =
                HttpSessionOAuth2AuthorizationRequestRepository()
            val CLIENT: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
                DefaultAuthorizationCodeTokenResponseClient()
            val USER_SERVICE: OAuth2UserService<OAuth2UserRequest, OAuth2User> = DefaultOAuth2UserService()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2Login {
                    userInfoEndpoint {
                        userService = USER_SERVICE
                    }
                    tokenEndpoint {
                        accessTokenResponseClient = CLIENT
                    }
                    authorizationEndpoint {
                        authorizationRequestRepository = REPOSITORY
                    }
                    redirectionEndpoint {
                        baseUri = "/callback"
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
