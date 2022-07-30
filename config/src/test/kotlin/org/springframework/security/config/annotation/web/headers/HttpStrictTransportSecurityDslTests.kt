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

import org.assertj.core.api.Assertions
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
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [HttpStrictTransportSecurityDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class HttpStrictTransportSecurityDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when hsts configured then headers in response`() {
        this.spring.register(HstsConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class HstsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity { }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when hsts configured with preload then preload in header`() {
        this.spring.register(HstsPreloadConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains ; preload") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class HstsPreloadConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        preload = true
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when hsts configured with max age then max age in header`() {
        this.spring.register(HstsMaxAgeConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=1 ; includeSubDomains") }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class HstsMaxAgeConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        maxAgeInSeconds = 1
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when hsts configured and does not match then hsts header not in response`() {
        this.spring.register(HstsCustomMatcherConfig::class.java).autowire()

        val result = this.mockMvc.get("/") {
            secure = true
        }.andReturn()

        Assertions.assertThat(result.response.headerNames).isEmpty()
    }

    @Configuration
    @EnableWebSecurity
    open class HstsCustomMatcherConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        requestMatcher = AntPathRequestMatcher("/secure/**")
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when hsts disabled then hsts header not in response`() {
        this.spring.register(HstsDisabledConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { doesNotExist(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class HstsDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    httpStrictTransportSecurity {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }
}
