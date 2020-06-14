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

package org.springframework.security.config.web.server

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.apache.commons.lang3.exception.ExceptionUtils
import org.assertj.core.api.Assertions.assertThat
import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebExceptionHandler
import reactor.core.publisher.Mono
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import javax.annotation.PreDestroy

/**
 * Tests for [ServerJwtDsl]
 *
 * @author Eleftheria Stein
 */
class ServerJwtDslTests {

    private val expired = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MzUwMzc4OTd9.jqZDDjfc2eysX44lHXEIr9XFd2S8vjIZHCccZU-dRWMRJNsQ1QN5VNnJGklqJBXJR4qgla6cmVqPOLkUHDb0sL0nxM5XuzQaG5ZzKP81RV88shFyAiT0fD-6nl1k-Fai-Fu-VkzSpNXgeONoTxDaYhdB-yxmgrgsApgmbOTE_9AcMk-FQDXQ-pL9kynccFGV0lZx4CA7cyknKN7KBxUilfIycvXODwgKCjj_1WddLTCNGYogJJSg__7NoxzqbyWd3udbHVjqYq7GsMMrGB4_2kBD4CkghOSNcRHbT_DIXowxfAVT7PAg7Q0E5ruZsr2zPZacEUDhJ6-wbvlA0FAOUg"
    private val messageReadToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2NrLXN1YmplY3QiLCJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6NDY4ODY0MTQxM30.cRl1bv_dDYcAN5U4NlIVKj8uu4mLMwjABF93P4dShiq-GQ-owzaqTSlB4YarNFgV3PKQvT9wxN1jBpGribvISljakoC0E8wDV-saDi8WxN-qvImYsn1zLzYFiZXCfRIxCmonJpydeiAPRxMTPtwnYDS9Ib0T_iA80TBGd-INhyxUUfrwRW5sqKRbjUciRJhpp7fW2ZYXmi9iPt3HDjRQA4IloJZ7f4-spt5Q9wl5HcQTv1t4XrX4eqhVbE5cCoIkFQnKPOc-jhVM44_eazLU6Xk-CCXP8C_UT5pX0luRS2cJrVFfHp2IR_AWxC-shItg6LNEmNFD4Zc-JLZcr0Q86Q"
    private val jwkSet = "{\n" +
            "  \"keys\":[\n" +
            "    {\n" +
            "      \"kty\":\"RSA\",\n" +
            "      \"e\":\"AQAB\",\n" +
            "      \"use\":\"sig\",\n" +
            "      \"kid\":\"one\",\n" +
            "      \"n\":\"0IUjrPZDz-3z0UE4ppcKU36v7hnh8FJjhu3lbJYj0qj9eZiwEJxi9HHUfSK1DhUQG7mJBbYTK1tPYCgre5EkfKh-64VhYUa-vz17zYCmuB8fFj4XHE3MLkWIG-AUn8hNbPzYYmiBTjfGnMKxLHjsbdTiF4mtn-85w366916R6midnAuiPD4HjZaZ1PAsuY60gr8bhMEDtJ8unz81hoQrozpBZJ6r8aR1PrsWb1OqPMloK9kAIutJNvWYKacp8WYAp2WWy72PxQ7Fb0eIA1br3A5dnp-Cln6JROJcZUIRJ-QvS6QONWeS2407uQmS-i-lybsqaH0ldYC7NBEBA5inPQ\"\n" +
            "    }\n" +
            "  ]\n" +
            "}\n"

    @Rule
    @JvmField
    val spring = SpringTestRule()

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `request when JWT configured with public key and valid token then responds with ok`() {
        this.spring.register(PublicKeyConfig::class.java, BaseController::class.java).autowire()

        this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(messageReadToken) }
                .exchange()
                .expectStatus().isOk
    }

    @Test
    fun `request when JWT configured with public key and expired token then responds with unauthorized`() {
        this.spring.register(PublicKeyConfig::class.java, BaseController::class.java).autowire()

        this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(expired) }
                .exchange()
                .expectStatus().isUnauthorized
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PublicKeyConfig {

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        publicKey = publicKey()
                    }
                }
            }
        }
    }

    @Test
    fun `jwt when using custom JWT decoded then custom decoded used`() {
        this.spring.register(CustomDecoderConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth("token") }
                .exchange()

        verify(CustomDecoderConfig.JWT_DECODER).decode("token")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomDecoderConfig {
        companion object {
            var JWT_DECODER: ReactiveJwtDecoder = mock(ReactiveJwtDecoder::class.java)
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwtDecoder = JWT_DECODER
                    }
                }
            }
        }
    }

    @Test
    fun `jwt when using custom JWK Set URI then custom URI used`() {
        this.spring.register(CustomJwkSetUriConfig::class.java).autowire()

        CustomJwkSetUriConfig.MOCK_WEB_SERVER.enqueue(MockResponse().setBody(jwkSet))

        this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(messageReadToken) }
                .exchange()

        val recordedRequest = CustomJwkSetUriConfig.MOCK_WEB_SERVER.takeRequest()
        assertThat(recordedRequest.path).isEqualTo("/.well-known/jwks.json")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomJwkSetUriConfig {
        companion object {
            var MOCK_WEB_SERVER: MockWebServer = MockWebServer()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwkSetUri = mockWebServer().url("/.well-known/jwks.json").toString()
                    }
                }
            }
        }

        @Bean
        open fun mockWebServer(): MockWebServer {
            return MOCK_WEB_SERVER
        }

        @PreDestroy
        open fun shutdown() {
            MOCK_WEB_SERVER.shutdown()
        }
    }

    @Test
    fun `jwt when using custom JWK Set URI than webClient set`() {
        this.spring.register(CustomJwkSetUriThanWebClientConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(messageReadToken) }
                .exchange()
                .returnResult(String::class.java)
                .responseBodyContent?.toString(Charsets.UTF_8) ?: "invalid"
        assertThat(result)
                .contains("method get(...) invoked")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomJwkSetUriThanWebClientConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwkSetUri = "http://foo/.well-known/jwks.json"
                        webClient = alwaysFailWebClient()
                    }
                }
            }
        }

        @Bean
        open fun globalErrorHandler() = GlobalErrorHandler()
    }

    @Test
    fun `jwt when using custom webClient than JWK Set URI set`() {
        this.spring.register(CustomWebClientThanJwkSetUriConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(messageReadToken) }
                .exchange()
                .returnResult(String::class.java)
                .responseBodyContent?.toString(Charsets.UTF_8) ?: "invalid"
        assertThat(result)
                .contains("method get(...) invoked")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomWebClientThanJwkSetUriConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        webClient = alwaysFailWebClient()
                        jwkSetUri = "http://foo/.well-known/jwks.json"
                    }
                }
            }
        }

        @Bean
        open fun globalErrorHandler() = GlobalErrorHandler()
    }

    @Test
    fun `jwt webClient and JWK Set URI replaced with jwtDecoder`() {
        this.spring.register(CustomWebClientAndJwkSetUriReplacedWithJwtDecoderConfig::class.java).autowire()

        val result = this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth(messageReadToken) }
                .exchange()
                .returnResult(String::class.java)
                .responseBodyContent?.toString(Charsets.UTF_8) ?: "invalid"
        assertThat(result)
                .contains("replaced jwtDecoder")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomWebClientAndJwkSetUriReplacedWithJwtDecoderConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        webClient = alwaysFailWebClient()
                        jwkSetUri = "http://foo/.well-known/jwks.json"
                        jwtDecoder = mock(ReactiveJwtDecoder::class.java).also {
                            `when`(it.decode(ArgumentMatchers.anyString())).thenReturn(Mono.error(java.lang.IllegalStateException("replaced jwtDecoder")))
                        }
                    }
                }
            }
        }

        @Bean
        open fun globalErrorHandler() = GlobalErrorHandler()
    }

    @Test
    fun `opaque token when custom JWT authentication converter then converter used`() {
        this.spring.register(CustomJwtAuthenticationConverterConfig::class.java).autowire()
        `when`(CustomJwtAuthenticationConverterConfig.DECODER.decode(anyString())).thenReturn(
                Mono.just(Jwt.withTokenValue("token")
                        .header("alg", "none")
                        .claim(IdTokenClaimNames.SUB, "user")
                        .build()))
        `when`(CustomJwtAuthenticationConverterConfig.CONVERTER.convert(any()))
                .thenReturn(Mono.just(TestingAuthenticationToken("test", "this", "ROLE")))

        this.client.get()
                .uri("/")
                .headers { headers: HttpHeaders -> headers.setBearerAuth("token") }
                .exchange()

        verify(CustomJwtAuthenticationConverterConfig.CONVERTER).convert(any())
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomJwtAuthenticationConverterConfig {
        companion object {
            var CONVERTER: Converter<Jwt, out Mono<AbstractAuthenticationToken>> = mock(Converter::class.java) as Converter<Jwt, out Mono<AbstractAuthenticationToken>>
            var DECODER: ReactiveJwtDecoder = mock(ReactiveJwtDecoder::class.java)
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oauth2ResourceServer {
                    jwt {
                        jwtAuthenticationConverter = CONVERTER
                    }
                }
            }
        }

        @Bean
        open fun jwtDecoder(): ReactiveJwtDecoder {
            return DECODER
        }
    }

    @RestController
    internal class BaseController {
        @GetMapping
        fun index() {
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

        private fun alwaysFailWebClient(): WebClient {
            return mock(WebClient::class.java) {
                when (it.method.name) {
                    "toString", "equals", "hashCode" -> {
                        return@mock it.callRealMethod()
                    }
                    else -> {
                        error("method ${it.method.name}(...) invoked")
                    }
                }
            }!!
        }

        @Order(-2)
        open class GlobalErrorHandler : WebExceptionHandler {
            override fun handle(serverWebExchange: ServerWebExchange, throwable: Throwable): Mono<Void> {
                val response = serverWebExchange.response
                response.statusCode = HttpStatus.INTERNAL_SERVER_ERROR
                response.headers.contentType = MediaType.TEXT_PLAIN
                val dataBuffer = response.bufferFactory()
                        .wrap(ExceptionUtils.getStackTrace(throwable).toByteArray())
                return response.writeWith(Mono.just(dataBuffer))
            }
        }
    }
}
