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

package org.springframework.security.config.web.server

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec

/**
 * Tests for [ServerOAuth2ResourceServerDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerOAuth2ResourceServerDslTests {
    private val validJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2NrLXN1YmplY3QiLCJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6NDY4ODY0MTQxM30.cRl1bv_dDYcAN5U4NlIVKj8uu4mLMwjABF93P4dShiq-GQ-owzaqTSlB4YarNFgV3PKQvT9wxN1jBpGribvISljakoC0E8wDV-saDi8WxN-qvImYsn1zLzYFiZXCfRIxCmonJpydeiAPRxMTPtwnYDS9Ib0T_iA80TBGd-INhyxUUfrwRW5sqKRbjUciRJhpp7fW2ZYXmi9iPt3HDjRQA4IloJZ7f4-spt5Q9wl5HcQTv1t4XrX4eqhVbE5cCoIkFQnKPOc-jhVM44_eazLU6Xk-CCXP8C_UT5pX0luRS2cJrVFfHp2IR_AWxC-shItg6LNEmNFD4Zc-JLZcr0Q86Q"

    @JvmField
    val spring = SpringTestContext(this)

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `request when custom access denied handler configured then custom handler used`() {
        this.spring.register(AccessDeniedHandlerConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .headers { it.setBearerAuth(validJwt) }
                .exchange()
                .expectStatus().isSeeOther
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AccessDeniedHandlerConfig {

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, hasAuthority("ADMIN"))
                }
                oauth2ResourceServer {
                    accessDeniedHandler = HttpStatusServerAccessDeniedHandler(HttpStatus.SEE_OTHER)
                    jwt {
                        publicKey = publicKey()
                    }
                }
            }
        }
    }

    @Test
    fun `request when custom entry point configured then custom entry point used`() {
        this.spring.register(AuthenticationEntryPointConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectStatus().isSeeOther
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationEntryPointConfig {

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    authenticationEntryPoint = HttpStatusServerEntryPoint(HttpStatus.SEE_OTHER)
                    jwt {
                        publicKey = publicKey()
                    }
                }
            }
        }
    }

    @Test
    fun `http basic when custom authentication failure handler then failure handler used`() {
        this.spring.register(AuthenticationFailureHandlerConfig::class.java).autowire()
        mockkObject(AuthenticationFailureHandlerConfig.FAILURE_HANDLER)
        every {
            AuthenticationFailureHandlerConfig.FAILURE_HANDLER.onAuthenticationFailure(any(), any())
        } returns Mono.empty()

        this.client.get()
            .uri("/")
            .header("Authorization", "Bearer token")
            .exchange()
            .expectStatus().isOk

        verify(exactly = 1) { AuthenticationFailureHandlerConfig.FAILURE_HANDLER.onAuthenticationFailure(any(), any()) }
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationFailureHandlerConfig {

        companion object {
            val FAILURE_HANDLER: ServerAuthenticationFailureHandler = MockServerAuthenticationFailureHandler()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    authenticationFailureHandler = FAILURE_HANDLER
                    jwt {
                        publicKey = publicKey()
                    }
                }
            }
        }
    }

    open class MockServerAuthenticationFailureHandler: ServerAuthenticationFailureHandler {
        override fun onAuthenticationFailure(
            webFilterExchange: WebFilterExchange?,
            exception: AuthenticationException?
        ): Mono<Void> {
            return Mono.empty()
        }

    }

    @Test
    fun `request when custom bearer token converter configured then custom converter used`() {
        this.spring.register(BearerTokenConverterConfig::class.java).autowire()
        mockkObject(BearerTokenConverterConfig.CONVERTER)
        every {
            BearerTokenConverterConfig.CONVERTER.convert(any())
        } returns Mono.empty()

        this.client.get()
                .uri("/")
                .headers { it.setBearerAuth(validJwt) }
                .exchange()

        verify(exactly = 1) { BearerTokenConverterConfig.CONVERTER.convert(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class BearerTokenConverterConfig {

        companion object {
            val CONVERTER: ServerBearerTokenAuthenticationConverter =
				ServerBearerTokenAuthenticationConverter()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    bearerTokenConverter = CONVERTER
                    jwt {
                        publicKey = publicKey()
                    }
                }
            }
        }
    }

    @Test
    fun `request when custom authentication manager resolver configured then custom resolver used`() {
        this.spring.register(AuthenticationManagerResolverConfig::class.java).autowire()
        mockkObject(AuthenticationManagerResolverConfig.RESOLVER)
        every {
            AuthenticationManagerResolverConfig.RESOLVER.resolve(any())
        } returns Mono.empty()

        this.client.get()
                .uri("/")
                .headers { it.setBearerAuth(validJwt) }
                .exchange()

        verify(exactly = 1) { AuthenticationManagerResolverConfig.RESOLVER.resolve(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationManagerResolverConfig {

        companion object {
            val RESOLVER: ReactiveAuthenticationManagerResolver<ServerWebExchange> = JwtIssuerReactiveAuthenticationManagerResolver("issuer")
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    authenticationManagerResolver = RESOLVER
                }
            }
        }
    }

    companion object {
        private fun publicKey(): RSAPublicKey {
            val modulus = "26323220897278656456354815752829448539647589990395639665273015355787577386000316054335559633864476469390247312823732994485311378484154955583861993455004584140858982659817218753831620205191028763754231454775026027780771426040997832758235764611119743390612035457533732596799927628476322029280486807310749948064176545712270582940917249337311592011920620009965129181413510845780806191965771671528886508636605814099711121026468495328702234901200169245493126030184941412539949521815665744267183140084667383643755535107759061065656273783542590997725982989978433493861515415520051342321336460543070448417126615154138673620797"
            val exponent = "65537"
            val spec = RSAPublicKeySpec(BigInteger(modulus), BigInteger(exponent))
            val factory = KeyFactory.getInstance("RSA")
            return factory.generatePublic(spec) as RSAPublicKey
        }
    }
}
