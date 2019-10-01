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

package org.springframework.security.config.web.servlet.oauth2.resourceserver

import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
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
                        jwtDecoder = mock(JwtDecoder::class.java)
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
    fun `opaque token when custom JWT authentication converter then converter used`() {
        this.spring.register(CustomJwtAuthenticationConverterConfig::class.java).autowire()
        `when`(CustomJwtAuthenticationConverterConfig.DECODER.decode(anyString())).thenReturn(
                Jwt.withTokenValue("token")
                        .header("alg", "none")
                        .claim(IdTokenClaimNames.SUB, "user")
                        .build())
        `when`(CustomJwtAuthenticationConverterConfig.CONVERTER.convert(any()))
                .thenReturn(TestingAuthenticationToken("test", "this", "ROLE"))
        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(CustomJwtAuthenticationConverterConfig.CONVERTER).convert(any())
    }

    @EnableWebSecurity
    open class CustomJwtAuthenticationConverterConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var CONVERTER: Converter<Jwt, out AbstractAuthenticationToken> = mock(Converter::class.java) as Converter<Jwt, out AbstractAuthenticationToken>
            var DECODER: JwtDecoder = mock(JwtDecoder::class.java)
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
        open fun jwtDecoder(): JwtDecoder {
            return DECODER
        }
    }
}
