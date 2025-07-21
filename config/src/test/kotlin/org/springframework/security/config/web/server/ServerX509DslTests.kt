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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ClassPathResource
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.ReactivePreAuthenticatedAuthenticationManager
import org.springframework.test.web.reactive.server.UserWebTestClientConfigurer.x509
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Tests for [ServerX509Dsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerX509DslTests {
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
    fun `x509 when configured with defaults then user authenticated with expected username`() {
        this.spring
                .register(X509DefaultConfig::class.java, UserDetailsConfig::class.java, UsernameController::class.java)
                .autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.client
                .mutateWith(x509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @Configuration
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
                .mutateWith(x509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @Configuration
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
                .mutateWith(x509(certificate))
                .get()
                .uri("/username")
                .exchange()
                .expectStatus().isOk
                .expectBody<String>().isEqualTo("rod")
    }

    @Configuration
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

    private fun <T : Certificate> loadCert(location: String): T {
        ClassPathResource(location).inputStream.use { inputStream ->
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(inputStream) as T
        }
    }
}
