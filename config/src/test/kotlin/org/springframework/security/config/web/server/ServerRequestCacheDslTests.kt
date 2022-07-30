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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

/**
 * Tests for [ServerRequestCacheDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerRequestCacheDslTests {
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
    fun `GET when request cache enabled then redirected to cached page`() {
        this.spring.register(RequestCacheConfig::class.java, UserDetailsConfig::class.java).autowire()
        mockkObject(RequestCacheConfig.REQUEST_CACHE)
        every {
            RequestCacheConfig.REQUEST_CACHE.removeMatchingRequest(any())
        } returns Mono.empty()

        this.client.get()
                .uri("/test")
                .exchange()

        verify(exactly = 1) { RequestCacheConfig.REQUEST_CACHE.saveRequest(any()) }
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class RequestCacheConfig {

        companion object {
            val REQUEST_CACHE: ServerRequestCache = WebSessionServerRequestCache()
        }

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                formLogin { }
                requestCache {
                    requestCache = REQUEST_CACHE
                }
            }
        }
    }

    @Configuration
    open class UserDetailsConfig {
        @Bean
        open fun userDetailsService(): MapReactiveUserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                    .username("user")
                    .password("password")
                    .roles("USER")
                    .build()
            return MapReactiveUserDetailsService(user)
        }
    }
}
