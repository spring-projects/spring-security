/*
 * Copyright 2004-present the original author or authors.
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

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerContentSecurityPolicyDsl]
 *
 * @author Eleftheria Stein
 * @author Ziqin Wang
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerContentSecurityPolicyDslTests {
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
    fun `request when content security policy configured then content security policy header in response`() {
        this.spring.register(ContentSecurityPolicyConfig::class.java).autowire()

        this.client.get()
                .uri("https://example.com")
                .exchange()
                .expectHeader().valueEquals(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, "default-src 'self'")
    }

    @Configuration
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

    @Configuration
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

    @Configuration
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

    /** @since 7.1 */
    @Test
    fun `request when configured with default nonce then CSP header with nonce in response`() {
        this.spring.register(CspDefaultNonceConfig::class.java).autowire()

        this.client.get()
            .uri("https://example.com/")
            .exchange()
            .expectHeader().valueMatches(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
                "^script-src 'self' 'nonce-[A-Za-z0-9+/]{22,}={0,2}'$")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CspDefaultNonceConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' 'nonce-{nonce}'"
                    }
                }
            }
        }
    }

    /** @since 7.1 */
    @Test
    fun `request when configured with custom nonce then CSP header with nonce in response`() {
        this.spring.register(CspCustomNonceConfig::class.java).autowire()

        this.client.get()
            .uri("https://example.com/")
            .exchange()
            .expectHeader().valueMatches(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
                "^script-src 'self' 'nonce-[A-Za-z0-9+/]{22,}={0,2}'$")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CspCustomNonceConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                headers {
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' 'nonce-{nonce}'"
                        nonceAttributeName = "CUSTOM_NONCE"
                    }
                }
            }
        }
    }

    /** @since 7.1 */
    @Test
    fun `request when configured with matcher then CSP header in response if matched`() {
        val headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY
        this.spring.register(CspMatcherConfig::class.java).autowire()

        this.client.get()
            .uri("https://example.com/")
            .accept(MediaType.TEXT_HTML)
            .exchange()
            .expectHeader().valueEquals(headerName, "default-src 'self'")
        this.client.get()
            .uri("https://example.com/")
            .accept(MediaType.TEXT_PLAIN)
            .exchange()
            .expectHeader().doesNotExist(headerName)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CspMatcherConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain = http {
            headers {
                contentSecurityPolicy {
                    policyDirectives = "default-src 'self'"
                    requireCspMatcher = ServerWebExchangeMatcher { exchange ->
                        if (MediaType.TEXT_HTML.isPresentIn(exchange.request.headers.accept))
                            ServerWebExchangeMatcher.MatchResult.match()
                        else
                            ServerWebExchangeMatcher.MatchResult.notMatch()
                    }
                }
            }
        }
    }

    /** @since 7.1 */
    @Test
    fun `request when configured with path matchers then CSP header in response if matched`() {
        val headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY
        this.spring.register(CspPathMatchersConfig::class.java).autowire()

        this.client.get()
            .uri("https://example.com/foo/bar")
            .exchange()
            .expectHeader().valueEquals(headerName, "default-src 'self'")
        this.client.get()
            .uri("https://example.com/bar/foo")
            .exchange()
            .expectHeader().valueEquals(headerName, "default-src 'self'")
        this.client.get()
            .uri("https://example.com/foobar")
            .exchange()
            .expectHeader().doesNotExist(headerName)
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CspPathMatchersConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain = http {
            headers {
                contentSecurityPolicy {
                    policyDirectives = "default-src 'self'"
                    requireCspMatchers("/foo/**", "/bar/**")
                }
            }
        }
    }

    /** @since 7.1 */
    @Test
    fun `when matchers overridden then fails to configure`() {
        assertThatThrownBy {
            this.spring.register(CspPathOverriddenMatchersConfig::class.java).autowire()
        }.hasRootCauseInstanceOf(IllegalStateException::class.java)
            .hasRootCauseMessage("RequireCspMatcher(s) is already configured")
    }

    @Configuration
    @EnableWebFluxSecurity
    @EnableWebFlux
    open class CspPathOverriddenMatchersConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain = http {
            headers {
                contentSecurityPolicy {
                    policyDirectives = "default-src 'self'"
                    requireCspMatcher = ServerWebExchangeMatchers.anyExchange()
                    requireCspMatchers("/**")
                }
            }
        }
    }

}
