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

package org.springframework.security.config.annotation.web.headers

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [XssProtectionConfigDsl]
 *
 * @author Eleftheria Stein
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension::class)
class XssProtectionConfigDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when XSS protection configured then header in response`() {
        this.spring.register(XssProtectionConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class XssProtectionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection { }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when XSS protection disabled then X-XSS-Protection header not in response`() {
        this.spring.register(XssProtectionDisabledFunctionConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { doesNotExist(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class XssProtectionDisabledFunctionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    xssProtection {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when XSS protection header value enabled then X-XSS-Protection header is 1`() {
        this.spring.register(XssProtectionHeaderValueEnabledFunctionConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class XssProtectionHeaderValueEnabledFunctionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection {
                        headerValue = XXssProtectionHeaderWriter.HeaderValue.ENABLED
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when XSS protection header value enabled_mode_block then X-XSS-Protection header is 1 and mode=block`() {
        this.spring.register(XssProtectionHeaderValueEnabledModeBlockFunctionConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1; mode=block") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class XssProtectionHeaderValueEnabledModeBlockFunctionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection {
                        headerValue = XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK
                    }
                }
            }
            return http.build()
        }
    }
}
