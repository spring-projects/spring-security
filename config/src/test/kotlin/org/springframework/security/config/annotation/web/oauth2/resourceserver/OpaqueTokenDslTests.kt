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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.TestingAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate

/**
 * Tests for [OpaqueTokenDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class OpaqueTokenDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    private val introspectionAuthenticationToken = BearerTokenAuthentication(
        DefaultOAuth2AuthenticatedPrincipal(
            mapOf(
                Pair(
                    JwtClaimNames.SUB,
                    "mock-test-subject"
                )
            ), emptyList()
        ),
        TestOAuth2AccessTokens.noScopes(), emptyList()
    )

    @Test
    fun `opaque token when defaults then uses introspection`() {
        this.spring.register(DefaultOpaqueConfig::class.java, AuthenticationController::class.java).autowire()
        mockkObject(DefaultOpaqueConfig.REST)
        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_JSON
        }
        val entity = ResponseEntity("{\n" +
                "  \"active\" : true,\n" +
                "  \"sub\": \"test-subject\",\n" +
                "  \"scope\": \"message:read\",\n" +
                "  \"exp\": 4683883211\n" +
                "}", headers, HttpStatus.OK)
        every {
            DefaultOpaqueConfig.REST.exchange(any(), eq(String::class.java))
        } returns entity

        this.mockMvc.get("/authenticated") {
            header("Authorization", "Bearer token")
        }.andExpect {
            status { isOk() }
            content { string("test-subject") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultOpaqueConfig {

        companion object {
            val REST: RestOperations = RestTemplate()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken { }
                }
            }
            return http.build()
        }

        @Bean
        open fun rest(): RestOperations = REST

        @Bean
        open fun tokenIntrospectionClient(): NimbusOpaqueTokenIntrospector {
            return NimbusOpaqueTokenIntrospector("https://example.org/introspect", REST)
        }
    }

    @Test
    fun `opaque token when custom introspector set then introspector used`() {
        this.spring.register(CustomIntrospectorConfig::class.java, AuthenticationController::class.java).autowire()
        mockkObject(CustomIntrospectorConfig.INTROSPECTOR)

        every {
            CustomIntrospectorConfig.INTROSPECTOR.introspect(any())
        } returns DefaultOAuth2AuthenticatedPrincipal(mapOf(Pair(JwtClaimNames.SUB, "mock-subject")), emptyList())

        this.mockMvc.get("/authenticated") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { CustomIntrospectorConfig.INTROSPECTOR.introspect("token") }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomIntrospectorConfig {

        companion object {
            val INTROSPECTOR: OpaqueTokenIntrospector = SpringOpaqueTokenIntrospector("uri", "clientId", "clientSecret")
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        introspector = INTROSPECTOR
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `opaque token when custom introspector set after client credentials then introspector used`() {
        this.spring.register(IntrospectorAfterClientCredentialsConfig::class.java, AuthenticationController::class.java).autowire()
        mockkObject(IntrospectorAfterClientCredentialsConfig.INTROSPECTOR)
        every {
            IntrospectorAfterClientCredentialsConfig.INTROSPECTOR.introspect(any())
        } returns DefaultOAuth2AuthenticatedPrincipal(mapOf(Pair(JwtClaimNames.SUB, "mock-subject")), emptyList())

        this.mockMvc.get("/authenticated") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { IntrospectorAfterClientCredentialsConfig.INTROSPECTOR.introspect("token") }
    }

    @Configuration
    @EnableWebSecurity
    open class IntrospectorAfterClientCredentialsConfig {

        companion object {
            val INTROSPECTOR: OpaqueTokenIntrospector = SpringOpaqueTokenIntrospector("uri", "clientId", "clientSecret")
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        introspectionUri = "/introspect"
                        introspectionClientCredentials("clientId", "clientSecret")
                        introspector = INTROSPECTOR
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `opaque token when custom authentication manager configured then used`() {
        this.spring.register(AuthenticationManagerConfig::class.java, AuthenticationController::class.java).autowire()
        mockkObject(AuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        every {
            AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any())
        } returns this.introspectionAuthenticationToken

        this.mockMvc.get("/authenticated") {
            header("Authorization", "Bearer token")
        }.andExpect {
            status { isOk() }
            content { string("mock-test-subject") }
        }

        verify(exactly = 1) { AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthenticationManagerConfig {

        companion object {
            val AUTHENTICATION_MANAGER: AuthenticationManager = ProviderManager(TestingAuthenticationProvider())
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken {
                        authenticationManager = AUTHENTICATION_MANAGER
                    }
                }
            }
            return http.build()
        }
    }

    @RestController
    class AuthenticationController {
        @GetMapping("/authenticated")
        fun authenticated(authentication: Authentication): String {
            return authentication.name
        }
    }
}
