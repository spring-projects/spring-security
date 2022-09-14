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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerContentTypeOptionsDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerContentTypeOptionsDslTests {
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
    fun `request when content type options configured then header in response`() {
        this.spring.register(ContentTypeOptionsConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().valueEquals(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class ContentTypeOptionsConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentTypeOptions { }
                }
            }
        }
    }

    @Test
    fun `request when content type options disabled then no content type options header in response`() {
        this.spring.register(ContentTypeOptionsDisabledConfig::class.java).autowire()

        this.client.get()
                .uri("/")
                .exchange()
                .expectHeader().doesNotExist(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class ContentTypeOptionsDisabledConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentTypeOptions {
                        disable()
                    }
                }
            }
        }
    }
}
