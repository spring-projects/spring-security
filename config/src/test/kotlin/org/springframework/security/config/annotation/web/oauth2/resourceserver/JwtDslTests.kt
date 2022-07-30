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
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.TestingAuthenticationProvider
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Tests for [JwtDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class JwtDslTests {

    private val jwtAuthenticationToken: Authentication = JwtAuthenticationToken(
        Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim(IdTokenClaimNames.SUB, "user")
            .subject("mock-test-subject")
            .build(),
        emptyList()
    )

    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `JWT when custom JWT decoder then bean not required`() {
        this.spring.register(CustomJwtDecoderConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class CustomJwtDecoderConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2ResourceServer {
                    jwt {
                        jwtDecoder = mockk()
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `JWT when custom jwkSetUri then bean not required`() {
        this.spring.register(CustomJwkSetUriConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class CustomJwkSetUriConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2ResourceServer {
                    jwt {
                        jwkSetUri = "https://jwk-uri"
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `JWT when custom JWT authentication converter then converter used`() {
        this.spring.register(CustomJwtAuthenticationConverterConfig::class.java).autowire()
        mockkObject(CustomJwtAuthenticationConverterConfig.CONVERTER)
        mockkObject(CustomJwtAuthenticationConverterConfig.DECODER)
        every {
            CustomJwtAuthenticationConverterConfig.DECODER.decode(any())
        } returns Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim(IdTokenClaimNames.SUB, "user")
            .build()
        every {
            CustomJwtAuthenticationConverterConfig.CONVERTER.convert(any())
        } returns TestingAuthenticationToken("test", "this", "ROLE")
        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { CustomJwtAuthenticationConverterConfig.CONVERTER.convert(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomJwtAuthenticationConverterConfig {

        companion object {
            val CONVERTER: Converter<Jwt, out AbstractAuthenticationToken> = MockConverter()
            val DECODER: JwtDecoder = MockJwtDecoder()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwtAuthenticationConverter = CONVERTER
                    }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder = DECODER
    }

    class MockConverter: Converter<Jwt, AbstractAuthenticationToken> {
        override fun convert(source: Jwt): AbstractAuthenticationToken {
            return TestingAuthenticationToken("a", "b",  "c")
        }
    }

    @Test
    fun `JWT when custom JWT decoder set after jwkSetUri then decoder used`() {
        this.spring.register(JwtDecoderAfterJwkSetUriConfig::class.java).autowire()
        mockkObject(JwtDecoderAfterJwkSetUriConfig.DECODER)
        every {
            JwtDecoderAfterJwkSetUriConfig.DECODER.decode(any())
        } returns Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim(IdTokenClaimNames.SUB, "user")
            .build()

        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { JwtDecoderAfterJwkSetUriConfig.DECODER.decode(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class JwtDecoderAfterJwkSetUriConfig {

        companion object {
            val DECODER: JwtDecoder = MockJwtDecoder()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwkSetUri = "https://jwk-uri"
                        jwtDecoder = DECODER
                    }
                }
            }
            return http.build()
        }
    }

    class MockJwtDecoder: JwtDecoder {
        override fun decode(token: String?): Jwt {
            return Jwt.withTokenValue("some tokenValue").build()
        }
    }

    @Test
    fun `JWT when custom authentication manager configured then used`() {
        this.spring.register(AuthenticationManagerConfig::class.java, AuthenticationController::class.java).autowire()
        mockkObject(AuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        every {
            AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any())
        } returns this.jwtAuthenticationToken

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
                    jwt {
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
