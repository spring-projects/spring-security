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

package org.springframework.security.config.web.servlet.oauth2.resourceserver

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
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
class OpaqueTokenDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

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

    @EnableWebSecurity
    open class DefaultOpaqueConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val REST: RestOperations = RestTemplate()
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    opaqueToken { }
                }
            }
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

    @EnableWebSecurity
    open class CustomIntrospectorConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val INTROSPECTOR: OpaqueTokenIntrospector = OpaqueTokenIntrospector {
                DefaultOAuth2AuthenticatedPrincipal(emptyMap(), emptyList())
            }
        }

        override fun configure(http: HttpSecurity) {
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

    @EnableWebSecurity
    open class IntrospectorAfterClientCredentialsConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val INTROSPECTOR: OpaqueTokenIntrospector = OpaqueTokenIntrospector {
                DefaultOAuth2AuthenticatedPrincipal(emptyMap(), emptyList())
            }
        }

        override fun configure(http: HttpSecurity) {
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
