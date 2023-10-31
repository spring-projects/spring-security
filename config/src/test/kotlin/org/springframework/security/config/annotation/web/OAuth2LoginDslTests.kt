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

package org.springframework.security.config.annotation.web

import io.mockk.every
import io.mockk.mockk
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
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource

/**
 * Tests for [OAuth2LoginDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class OAuth2LoginDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2Login when custom client registration repository then bean is not required`() {
        this.spring.register(ClientRepoConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class ClientRepoConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    clientRegistrationRepository = InMemoryClientRegistrationRepository(
                            CommonOAuth2Provider.GOOGLE
                                    .getBuilder("google").clientId("clientId").clientSecret("clientSecret")
                                    .build()
                    )
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login page when oAuth2Login configured then default login page created`() {
        this.spring.register(OAuth2LoginConfig::class.java, ClientConfig::class.java).autowire()

        this.mockMvc.get("/login")
                .andExpect {
                    status { isOk() }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class OAuth2LoginConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login { }
            }
            return http.build()
        }
    }

    @Test
    fun `login page when custom login page then redirected to custom page`() {
        this.spring.register(LoginPageConfig::class.java, ClientConfig::class.java).autowire()

        this.mockMvc.get("/custom-login")
                .andExpect {
                    status { isOk() }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class LoginPageConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    loginPage = "/custom-login"
                }
            }
            return http.build()
        }

        @RestController
        class LoginController {
            @GetMapping("/custom-login")
            fun loginPage() { }
        }
    }

    @Test
    fun `oauth2Login when custom authentication details source then used`() {
        this.spring
            .register(CustomAuthenticationDetailsSourceConfig::class.java, ClientConfig::class.java)
            .autowire()
        mockkObject(CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE)
        every {
            CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE.buildDetails(any())
        } returns mockk()
        mockkObject(CustomAuthenticationDetailsSourceConfig.AUTHORIZATION_REQUEST_REPOSITORY)
        every {
            CustomAuthenticationDetailsSourceConfig.AUTHORIZATION_REQUEST_REPOSITORY.removeAuthorizationRequest(any(), any())
        } returns OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("/")
            .clientId("clientId")
            .redirectUri("/")
            .attributes { attributes -> attributes[OAuth2ParameterNames.REGISTRATION_ID] = "google" }
            .build()

        this.mockMvc.post("/login/oauth2/code/google") {
            param(OAuth2ParameterNames.CODE, "code")
            param(OAuth2ParameterNames.STATE, "state")
            with(csrf())
        }
        .andExpect {
            status { is3xxRedirection() }
        }

        verify(exactly = 1) { CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE.buildDetails(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomAuthenticationDetailsSourceConfig {

        companion object {
            val AUTHENTICATION_DETAILS_SOURCE = WebAuthenticationDetailsSource()
            val AUTHORIZATION_REQUEST_REPOSITORY = HttpSessionOAuth2AuthorizationRequestRepository()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login {
                    authenticationDetailsSource = AUTHENTICATION_DETAILS_SOURCE
                    authorizationEndpoint {
                        authorizationRequestRepository = AUTHORIZATION_REQUEST_REPOSITORY
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
