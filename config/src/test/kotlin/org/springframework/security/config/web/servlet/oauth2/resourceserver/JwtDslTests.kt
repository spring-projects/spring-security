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
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [JwtDsl]
 *
 * @author Eleftheria Stein
 */
class JwtDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `JWT when custom JWT decoder then bean not required`() {
        this.spring.register(CustomJwtDecoderConfig::class.java).autowire()
    }

    @EnableWebSecurity
    open class CustomJwtDecoderConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                oauth2ResourceServer {
                    jwt {
                        jwtDecoder = mockk()
                    }
                }
            }
        }
    }

    @Test
    fun `JWT when custom jwkSetUri then bean not required`() {
        this.spring.register(CustomJwkSetUriConfig::class.java).autowire()
    }

    @EnableWebSecurity
    open class CustomJwkSetUriConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                oauth2ResourceServer {
                    jwt {
                        jwkSetUri = "https://jwk-uri"
                    }
                }
            }
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

    @EnableWebSecurity
    open class CustomJwtAuthenticationConverterConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val CONVERTER: Converter<Jwt, out AbstractAuthenticationToken> = Converter { _ ->
                TestingAuthenticationToken("a", "b",  "c")
            }
            val DECODER: JwtDecoder = JwtDecoder { Jwt.withTokenValue("some tokenValue").build() }
        }

        override fun configure(http: HttpSecurity) {
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
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder = DECODER
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

    @EnableWebSecurity
    open class JwtDecoderAfterJwkSetUriConfig : WebSecurityConfigurerAdapter() {

        companion object {
            val DECODER: JwtDecoder = JwtDecoder { Jwt.withTokenValue("some tokenValue").build() }
        }

        override fun configure(http: HttpSecurity) {
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
        }
    }
}
