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
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerContentSecurityPolicyDsl]
 *
 * @author Eleftheria Stein
 */
class ServerContentSecurityPolicyDslTests {
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
    fun `request when content security policy configured then content security policy header in response`() {
        this.spring.register(ContentSecurityPolicyConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, "default-src 'self'")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class ContentSecurityPolicyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentSecurityPolicy { }
                }
            }
        }
    }

    @Test
    fun `request when custom policy directives then custom policy directive in response header`() {
        this.spring.register(CustomPolicyDirectivesConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, "default-src 'self'; script-src trustedscripts.example.com")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CustomPolicyDirectivesConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'; script-src trustedscripts.example.com"
                    }
                }
            }
        }
    }

    @Test
    fun `request when report only configured then content security policy report only header in response`() {
        this.spring.register(ReportOnlyConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY_REPORT_ONLY, "default-src 'self'")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class ReportOnlyConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentSecurityPolicy {
                        reportOnly = true
                    }
                }
            }
        }
    }
}
