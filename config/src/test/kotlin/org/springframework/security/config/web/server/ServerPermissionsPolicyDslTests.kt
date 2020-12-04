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

import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerPermissionsPolicyDsl]
 *
 * @author Christophe Gilles
 */
class ServerPermissionsPolicyDslTests {
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
    fun `request when permissions policy configured then permissions policy header in response`() {
        this.spring.register(PermissionsPolicyConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().doesNotExist("Permissions-Policy")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PermissionsPolicyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    permissionsPolicy { }
                }
            }
        }
    }

    @Test
    fun `request when custom policy configured then custom policy in response header`() {
        this.spring.register(CustomPolicyConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().valueEquals("Permissions-Policy", "geolocation=(self)")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomPolicyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    permissionsPolicy {
                        policy = "geolocation=(self)"
                    }
                }
            }
        }
    }
}
