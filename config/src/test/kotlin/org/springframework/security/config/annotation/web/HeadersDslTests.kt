/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.StaticHeadersWriter
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [HeadersDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class HeadersDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when defaults enabled then default headers in response`() {
        this.spring.register(DefaultHeadersConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff") }
            header { string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name) }
            header { string(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains") }
            header { string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate") }
            header { string(HttpHeaders.EXPIRES, "0") }
            header { string(HttpHeaders.PRAGMA, "no-cache") }
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultHeadersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers { }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when feature policy configured then header in response`() {
        this.spring.register(FeaturePolicyConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string("Feature-Policy", "geolocation 'self'") }
                }
    }

    @Configuration
    @EnableWebSecurity
    @Suppress("DEPRECATION")
    open class FeaturePolicyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    featurePolicy(policyDirectives = "geolocation 'self'")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when permissions policy configured then header in response`() {
        this.spring.register(PermissionsPolicyConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string("Permissions-Policy", "geolocation=(self)") }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class PermissionsPolicyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    permissionsPolicy {
                        policy = "geolocation=(self)"
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when headers disabled then no security headers are in the response`() {
        this.spring.register(HeadersDisabledConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { doesNotExist(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS) }
                    header { doesNotExist(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS) }
                    header { doesNotExist(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY) }
                    header { doesNotExist(HttpHeaders.CACHE_CONTROL) }
                    header { doesNotExist(HttpHeaders.EXPIRES) }
                    header { doesNotExist(HttpHeaders.PRAGMA) }
                    header { doesNotExist(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION) }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class HeadersDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    disable()
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when custom header writer then custom header in response`() {
        this.spring.register(HeaderWriterConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string("custom-header", "custom-value") }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class HeaderWriterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    addHeaderWriter(StaticHeadersWriter("custom-header", "custom-value"))
                }
            }
            return http.build()
        }
    }
}
