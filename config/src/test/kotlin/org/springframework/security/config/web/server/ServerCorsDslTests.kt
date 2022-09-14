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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerCorsDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerCorsDslTests {
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
    fun `request when CORS configured using bean then Access-Control-Allow-Origin header in response`() {
        this.spring.register(CorsBeanConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .header(HttpHeaders.ORIGIN, "https://origin.example.com")
                .exchange()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "*")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CorsBeanConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                cors { }
            }
        }

        @Bean
        open fun corsConfigurationSource(): CorsConfigurationSource {
            val source = UrlBasedCorsConfigurationSource()
            val corsConfiguration = CorsConfiguration()
            corsConfiguration.allowedOrigins = listOf("*")
            source.registerCorsConfiguration("/**", corsConfiguration)
            return source
        }
    }

    @Test
    fun `request when CORS configured using source then Access-Control-Allow-Origin header in response`() {
        this.spring.register(CorsSourceConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .header(HttpHeaders.ORIGIN, "https://origin.example.com")
                .exchange()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "*")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CorsSourceConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            val source = UrlBasedCorsConfigurationSource()
            val corsConfiguration = CorsConfiguration()
            corsConfiguration.allowedOrigins = listOf("*")
            source.registerCorsConfiguration("/**", corsConfiguration)
            return http {
                cors {
                    configurationSource = source
                }
            }
        }
    }

    @Test
    fun `request when CORS disabled then no Access-Control-Allow-Origin header in response`() {
        this.spring.register(CorsDisabledConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .header(HttpHeaders.ORIGIN, "https://origin.example.com")
                .exchange()
                .expectHeader().doesNotExist("Access-Control-Allow-Origin")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CorsDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                cors {
                    disable()
                }
            }
        }
    }
}
