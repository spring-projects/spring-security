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
import io.mockk.mockk
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ClassPathResource
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.http.server.reactive.SslInfo
import org.springframework.lang.Nullable
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.ReactivePreAuthenticatedAuthenticationManager
import org.springframework.test.web.reactive.server.MockServerConfigurer
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.WebTestClientConfigurer
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.ServerWebExchangeDecorator
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.server.adapter.WebHttpHandlerBuilder
import reactor.core.publisher.Mono

/**
 * Tests for [ServerX509Dsl]
 *
 * @author Eleftheria Stein
 */
class ServerX509DslTests {
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
    fun `x509 when configured with defaults then user authenticated with expected username`() {
        this.spring
                .register(X509DefaultConfig::class.java, UserDetailsConfig::class.java, UsernameController::class.java)
                .autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.client
                .mutateWith(mockX509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class X509DefaultConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                x509 { }
            }
        }
    }

    @Test
    fun `x509 when principal extractor customized then custom principal extractor used`() {
        this.spring
                .register(PrincipalExtractorConfig::class.java, UserDetailsConfig::class.java, UsernameController::class.java)
                .autowire()
        val certificate = loadCert<X509Certificate>("rodatexampledotcom.cer")

        this.client
                .mutateWith(mockX509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PrincipalExtractorConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            val customPrincipalExtractor = SubjectDnX509PrincipalExtractor()
            customPrincipalExtractor.setSubjectDnRegex("CN=(.*?)@example.com(?:,|$)")
            return http {
                x509 {
                    principalExtractor = customPrincipalExtractor
                }
            }
        }
    }

    @Test
    fun `x509 when authentication manager customized then custom authentication manager used`() {
        this.spring
                .register(AuthenticationManagerConfig::class.java, UsernameController::class.java)
                .autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.client
                .mutateWith(mockX509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class AuthenticationManagerConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                x509 {
                    authenticationManager = ReactivePreAuthenticatedAuthenticationManager(userDetailsService())
                }
            }
        }

        fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(user)
        }
    }

    @RestController
    class UsernameController {
        @GetMapping("/username")
        fun principal(@AuthenticationPrincipal user: User?): String {
            return user!!.username
        }
    }

    @Configuration
    open class UserDetailsConfig {
        @Bean
        open fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(user)
        }
    }

    private fun mockX509(certificate: X509Certificate): X509Mutator {
        return X509Mutator(certificate)
    }

    private class X509Mutator internal constructor(private var certificate: X509Certificate) : WebTestClientConfigurer, MockServerConfigurer {

        override fun afterConfigurerAdded(builder: WebTestClient.Builder,
                                          @Nullable httpHandlerBuilder: WebHttpHandlerBuilder?,
                                          @Nullable connector: ClientHttpConnector?) {
            val filter = SetSslInfoWebFilter(certificate)
            httpHandlerBuilder!!.filters { filters: MutableList<WebFilter?> -> filters.add(0, filter) }
        }
    }

    private class SetSslInfoWebFilter(var certificate: X509Certificate) : WebFilter {

        override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
            return chain.filter(decorate(exchange))
        }

        private fun decorate(exchange: ServerWebExchange): ServerWebExchange {
            val decorated: ServerHttpRequestDecorator = object : ServerHttpRequestDecorator(exchange.request) {
                override fun getSslInfo(): SslInfo {
                    val sslInfo: SslInfo = mockk()
                    every { sslInfo.sessionId } returns "sessionId"
                    every { sslInfo.peerCertificates } returns arrayOf(certificate)
                    return sslInfo
                }
            }
            return object : ServerWebExchangeDecorator(exchange) {
                override fun getRequest(): org.springframework.http.server.reactive.ServerHttpRequest {
                    return decorated
                }
            }
        }
    }

    private fun <T : Certificate> loadCert(location: String): T {
        ClassPathResource(location).inputStream.use { inputStream ->
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(inputStream) as T
        }
    }
}
