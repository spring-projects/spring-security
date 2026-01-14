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

package org.springframework.security.config.annotation.web.headers

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.hamcrest.Matchers.matchesPattern
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [ContentSecurityPolicyDsl]
 *
 * @author Eleftheria Stein
 * @author Ziqin Wang
 */
@ExtendWith(SpringTestContextExtension::class)
class ContentSecurityPolicyDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when content security policy configured then header in response`() {
        this.spring.register(ContentSecurityPolicyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy { }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when content security policy configured with custom policy directives then custom directives in header`() {
        this.spring.register(CustomPolicyDirectivesConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    "default-src 'self'; script-src trustedscripts.example.com")
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomPolicyDirectivesConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'; script-src trustedscripts.example.com"
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when report only content security policy report only header in response`() {
        this.spring.register(ReportOnlyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER,
                    "default-src 'self'")
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ReportOnlyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        reportOnly = true
                    }
                }
            }
            return http.build()
        }
    }

    /** @since 7.1 */
    @Test
    fun `headers when content security policy configured with default nonce attribute then header in response`() {
        this.spring.register(ContentSecurityPolicyDefaultNonceConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    matchesPattern("^script-src 'self' 'nonce-[A-Za-z0-9+/]{22,}={0,2}'$"))
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyDefaultNonceConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' 'nonce-{nonce}'"
                    }
                }
            }
            return http.build()
        }
    }

    /** @since 7.1 */
    @Test
    fun `headers when content security policy configured with custom nonce attribute then header in response`() {
        this.spring.register(ContentSecurityPolicyCustomNonceConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    matchesPattern("^script-src 'self' 'nonce-[A-Za-z0-9+/]{22,}={0,2}'$"))
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyCustomNonceConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "script-src 'self' 'nonce-{nonce}'"
                        nonceAttributeName = "CUSTOM_NONCE"
                    }
                }
            }
            return http.build()
        }
    }

    /** @since 7.1 */
    @Test
    fun `headers when content security policy configured with matcher then header in response if matched`() {
        this.spring.register(ContentSecurityPolicyMatcherConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
            accept = MediaType.TEXT_HTML
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    "default-src 'self'")
            }
        }
        this.mockMvc.get("/") {
            secure = true
            accept = MediaType.TEXT_PLAIN
        }.andExpect {
            header { doesNotExist(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyMatcherConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'"
                        requireCspMatcher = RequestMatcher { request ->
                            val accepted = MediaType.parseMediaTypes(request.getHeader(HttpHeaders.ACCEPT))
                            MediaType.TEXT_HTML.isPresentIn(accepted)
                        }
                    }
                }
            }
            return http.build()
        }
    }

    /** @since 7.1 */
    @Test
    fun `headers when content security policy configured with path matchers then header in response if matched`() {
        this.spring.register(ContentSecurityPolicyPathMatchersConfig::class.java).autowire()

        this.mockMvc.get("/foo/bar") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    "default-src 'self'")
            }
        }
        this.mockMvc.get("/bar/foo") {
            secure = true
        }.andExpect {
            header {
                string(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER,
                    "default-src 'self'")
            }
        }
        this.mockMvc.get("/foobar") {
            secure = true
        }.andExpect {
            header { doesNotExist(ContentSecurityPolicyHeaderWriter.CONTENT_SECURITY_POLICY_HEADER) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyPathMatchersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'"
                        requireCspMatchers("/foo/**", "/bar/**")
                    }
                }
            }
            return http.build()
        }
    }

    /** @since 7.1 */
    @Test
    fun `headers when content security policy configured with overridden matchers then throws`() {
        assertThatThrownBy {
            this.spring.register(ContentSecurityPolicyOverriddenMatchersConfig::class.java).autowire()
        }.hasRootCauseInstanceOf(IllegalStateException::class.java)
            .hasRootCauseMessage("RequireCspMatcher(s) is already configured")
    }

    @Configuration
    @EnableWebSecurity
    open class ContentSecurityPolicyOverriddenMatchersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'"
                        requireCspMatcher = AnyRequestMatcher.INSTANCE
                        requireCspMatchers("/**")
                    }
                }
            }
            return http.build()
        }
    }

}
