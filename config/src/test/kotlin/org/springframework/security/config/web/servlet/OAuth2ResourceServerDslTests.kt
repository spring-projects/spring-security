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

import org.assertj.core.api.Assertions
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.*
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.SUB
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import javax.servlet.http.HttpServletRequest

/**
 * Tests for [OAuth2ResourceServerDsl]
 *
 * @author Eleftheria Stein
 */
class OAuth2ResourceServerDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    private val JWT: Jwt = Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim(SUB, "user")
            .build()

    @Test
    fun `oauth2Resource server when custom entry point then entry point used`() {
        this.spring.register(EntryPointConfig::class.java).autowire()

        this.mockMvc.get("/")

        verify(EntryPointConfig.ENTRY_POINT).commence(any(), any(), any())
    }

    @EnableWebSecurity
    open class EntryPointConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var ENTRY_POINT: AuthenticationEntryPoint = mock(AuthenticationEntryPoint::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationEntryPoint = ENTRY_POINT
                    jwt { }
                }
            }
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder {
            return mock(JwtDecoder::class.java)
        }
    }

    @Test
    fun `oauth2Resource server when custom bearer token resolver then resolver used`() {
        this.spring.register(BearerTokenResolverConfig::class.java).autowire()

        this.mockMvc.get("/")

        verify(BearerTokenResolverConfig.RESOLVER).resolve(any())
    }

    @EnableWebSecurity
    open class BearerTokenResolverConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var RESOLVER: BearerTokenResolver = mock(BearerTokenResolver::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    bearerTokenResolver = RESOLVER
                    jwt { }
                }
            }
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder {
            return mock(JwtDecoder::class.java)
        }
    }

    @Test
    fun `oauth2Resource server when custom access denied handler then handler used`() {
        this.spring.register(AccessDeniedHandlerConfig::class.java).autowire()
        `when`(AccessDeniedHandlerConfig.DECODER.decode(anyString())).thenReturn(JWT)

        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(AccessDeniedHandlerConfig.DENIED_HANDLER).handle(any(), any(), any())
    }

    @EnableWebSecurity
    open class AccessDeniedHandlerConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var DENIED_HANDLER: AccessDeniedHandler = mock(AccessDeniedHandler::class.java)
            var DECODER: JwtDecoder = mock(JwtDecoder::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, denyAll)
                }
                oauth2ResourceServer {
                    accessDeniedHandler = DENIED_HANDLER
                    jwt { }
                }
            }
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder {
            return DECODER
        }
    }

    @Test
    fun `oauth2Resource server when custom authentication manager resolver then resolver used`() {
        this.spring.register(AuthenticationManagerResolverConfig::class.java).autowire()
        `when`(AuthenticationManagerResolverConfig.RESOLVER.resolve(any())).thenReturn(
                AuthenticationManager {
                    JwtAuthenticationToken(JWT)
                }
        )

        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(AuthenticationManagerResolverConfig.RESOLVER).resolve(any())
    }

    @EnableWebSecurity
    open class AuthenticationManagerResolverConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var RESOLVER: AuthenticationManagerResolver<*> = mock(AuthenticationManagerResolver::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationManagerResolver = RESOLVER as AuthenticationManagerResolver<HttpServletRequest>
                }
            }
        }
    }

    @Test
    fun `oauth2Resource server when custom authentication manager resolver and opaque then exception`() {
        Assertions.assertThatExceptionOfType(BeanCreationException::class.java)
                .isThrownBy { spring.register(AuthenticationManagerResolverAndOpaqueConfig::class.java).autowire() }
                .withMessageContaining("authenticationManagerResolver")
    }

    @EnableWebSecurity
    open class AuthenticationManagerResolverAndOpaqueConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationManagerResolver = mock(AuthenticationManagerResolver::class.java)
                            as AuthenticationManagerResolver<HttpServletRequest>
                    opaqueToken { }
                }
            }
        }
    }
}
