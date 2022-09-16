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
import jakarta.servlet.http.HttpServletRequest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.SUB
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [OAuth2ResourceServerDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class OAuth2ResourceServerDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    private val JWT: Jwt = Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim(SUB, "user")
            .build()

    @Test
    fun `oauth2Resource server when custom entry point then entry point used`() {
        this.spring.register(EntryPointConfig::class.java).autowire()
        mockkObject(EntryPointConfig.ENTRY_POINT)
        every { EntryPointConfig.ENTRY_POINT.commence(any(), any(), any()) } returns Unit

        this.mockMvc.get("/")

        verify(exactly = 1) { EntryPointConfig.ENTRY_POINT.commence(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class EntryPointConfig {

        companion object {
            val ENTRY_POINT: AuthenticationEntryPoint = HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationEntryPoint = ENTRY_POINT
                    jwt { }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder = mockk()
    }

    @Test
    fun `oauth2Resource server when custom bearer token resolver then resolver used`() {
        this.spring.register(BearerTokenResolverConfig::class.java).autowire()
        mockkObject(BearerTokenResolverConfig.RESOLVER)
        mockkObject(BearerTokenResolverConfig.DECODER)
        every { BearerTokenResolverConfig.RESOLVER.resolve(any()) } returns "anything"
        every { BearerTokenResolverConfig.DECODER.decode(any()) } returns JWT

        this.mockMvc.get("/")

        verify(exactly = 1) { BearerTokenResolverConfig.RESOLVER.resolve(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class BearerTokenResolverConfig {

        companion object {
            val RESOLVER: BearerTokenResolver = DefaultBearerTokenResolver()
            val DECODER: JwtDecoder = MockJwtDecoder()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    bearerTokenResolver = RESOLVER
                    jwt { }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder = DECODER
    }

    class MockJwtDecoder: JwtDecoder {
        override fun decode(token: String?): Jwt {
            return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim(SUB, "user")
                .build()
        }

    }

    @Test
    fun `oauth2Resource server when custom access denied handler then handler used`() {
        this.spring.register(AccessDeniedHandlerConfig::class.java).autowire()
        mockkObject(AccessDeniedHandlerConfig.DENIED_HANDLER)
        mockkObject(AccessDeniedHandlerConfig.DECODER)
        every {
            AccessDeniedHandlerConfig.DECODER.decode(any())
        } returns JWT
        every {
            AccessDeniedHandlerConfig.DENIED_HANDLER.handle(any(), any(), any())
        } returns Unit

        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { AccessDeniedHandlerConfig.DENIED_HANDLER.handle(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class AccessDeniedHandlerConfig {

        companion object {
            val DECODER: JwtDecoder = MockJwtDecoder()
            val DENIED_HANDLER: AccessDeniedHandler = AccessDeniedHandlerImpl()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, denyAll)
                }
                oauth2ResourceServer {
                    accessDeniedHandler = DENIED_HANDLER
                    jwt { }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder = DECODER
    }

    @Test
    fun `oauth2Resource server when custom authentication manager resolver then resolver used`() {
        this.spring.register(AuthenticationManagerResolverConfig::class.java).autowire()
        mockkObject(AuthenticationManagerResolverConfig.RESOLVER)
        every {
            AuthenticationManagerResolverConfig.RESOLVER.resolve(any())
        } returns MockAuthenticationManager(JwtAuthenticationToken(JWT))

        this.mockMvc.get("/") {
            header("Authorization", "Bearer token")
        }

        verify(exactly = 1) { AuthenticationManagerResolverConfig.RESOLVER.resolve(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthenticationManagerResolverConfig {

        companion object {
            val RESOLVER: AuthenticationManagerResolver<HttpServletRequest> =
                JwtIssuerAuthenticationManagerResolver("issuer")
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationManagerResolver = RESOLVER
                }
            }
            return http.build()
        }
    }

    class MockAuthenticationManager(var authentication: Authentication) : AuthenticationManager {

        override fun authenticate(authentication: Authentication?): Authentication {
            return this.authentication
        }

    }

    @Test
    fun `oauth2Resource server when custom authentication manager resolver and opaque then exception`() {
        Assertions.assertThatExceptionOfType(BeanCreationException::class.java)
                .isThrownBy { spring.register(AuthenticationManagerResolverAndOpaqueConfig::class.java).autowire() }
                .withMessageContaining("authenticationManagerResolver")
    }

    @Configuration
    @EnableWebSecurity
    open class AuthenticationManagerResolverAndOpaqueConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    authenticationManagerResolver = mockk()
                    opaqueToken { }
                }
            }
            return http.build()
        }
    }
}
