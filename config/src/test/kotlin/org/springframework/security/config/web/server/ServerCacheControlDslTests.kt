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
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerCacheControlDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerCacheControlDslTests {
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
    fun `request when cache control configured then cache headers in response`() {
        this.spring.register(CacheControlConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().valueEquals(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate")
                .expectHeader().valueEquals(HttpHeaders.EXPIRES, "0")
                .expectHeader().valueEquals(HttpHeaders.PRAGMA, "no-cache")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CacheControlConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    cache { }
                }
            }
        }
    }

    @Test
    fun `request when cache control disabled then no cache headers in response`() {
        this.spring.register(CacheControlDisabledConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().doesNotExist(HttpHeaders.CACHE_CONTROL)
                .expectHeader().doesNotExist(HttpHeaders.EXPIRES)
                .expectHeader().doesNotExist(HttpHeaders.PRAGMA)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CacheControlDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    cache {
                        disable()
                    }
                }
            }
        }
    }
}
