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

package org.springframework.security.config.web.servlet.headers

import org.assertj.core.api.Assertions
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [HttpStrictTransportSecurityDsl]
 *
 * @author Eleftheria Stein
 */
class HttpStrictTransportSecurityDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

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

    @EnableWebSecurity
    open class HstsConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity { }
                }
            }
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

    @EnableWebSecurity
    open class HstsPreloadConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        preload = true
                    }
                }
            }
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

    @EnableWebSecurity
    open class HstsMaxAgeConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        maxAgeInSeconds = 1
                    }
                }
            }
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

    @EnableWebSecurity
    open class HstsCustomMatcherConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpStrictTransportSecurity {
                        requestMatcher = AntPathRequestMatcher("/secure/**")
                    }
                }
            }
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

    @EnableWebSecurity
    open class HstsDisabledConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    httpStrictTransportSecurity {
                        disable()
                    }
                }
            }
        }
    }
}
