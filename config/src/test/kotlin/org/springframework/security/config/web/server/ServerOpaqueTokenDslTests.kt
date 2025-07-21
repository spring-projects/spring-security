/*
 * Copyright 2002-2025 the original author or authors.
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
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import jakarta.annotation.PreDestroy
import org.springframework.context.annotation.Configuration

/**
 * Tests for [ServerOpaqueTokenDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerOpaqueTokenDslTests {
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
    fun `opaque token when using defaults then uses introspector bean`() {
        this.spring.register(IntrospectorBeanConfig::class.java).autowire()

        IntrospectorBeanConfig.MOCK_WEB_SERVER.enqueue(MockResponse())

        this.client.get()
                .uri("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .exchange()

        val recordedRequest = IntrospectorBeanConfig.MOCK_WEB_SERVER.takeRequest()
        assertThat(recordedRequest.path).isEqualTo("/introspect")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class IntrospectorBeanConfig {
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
                    opaqueToken { }
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

        @Bean
        open fun tokenIntrospectionClient(): ReactiveOpaqueTokenIntrospector {
            return SpringReactiveOpaqueTokenIntrospector(mockWebServer().url("/introspect").toString(), "client", "secret")
        }
    }

    @Test
    fun `opaque token when using custom introspector then introspector used`() {
        this.spring.register(CustomIntrospectorConfig::class.java).autowire()

        CustomIntrospectorConfig.MOCK_WEB_SERVER.enqueue(MockResponse())

        this.client.get()
                .uri("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .exchange()

        val recordedRequest = CustomIntrospectorConfig.MOCK_WEB_SERVER.takeRequest()
        assertThat(recordedRequest.path).isEqualTo("/introspector")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomIntrospectorConfig {
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
                    opaqueToken {
                        introspector = SpringReactiveOpaqueTokenIntrospector(mockWebServer().url("/introspector").toString(), "client", "secret")
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
    fun `opaque token when using custom introspection URI and credentials then custom used`() {
        this.spring.register(CustomIntrospectionUriAndCredentialsConfig::class.java).autowire()

        CustomIntrospectionUriAndCredentialsConfig.MOCK_WEB_SERVER.enqueue(MockResponse())

        this.client.get()
                .uri("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .exchange()

        val recordedRequest = CustomIntrospectionUriAndCredentialsConfig.MOCK_WEB_SERVER.takeRequest()
        assertThat(recordedRequest.path).isEqualTo("/introspection-uri")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomIntrospectionUriAndCredentialsConfig {
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
                    opaqueToken {
                        introspectionUri = mockWebServer().url("/introspection-uri").toString()
                        introspectionClientCredentials("client", "secret")
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
}
