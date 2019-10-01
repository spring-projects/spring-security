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

import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [XssProtectionConfigDsl]
 *
 * @author Eleftheria Stein
 */
class XssProtectionConfigDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when XSS protection configured then header in response`() {
        this.spring.register(XssProtectionConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1; mode=block") }
        }
    }

    @EnableWebSecurity
    open class XssProtectionConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection { }
                }
            }
        }
    }

    @Test
    fun `headers when XSS protection with block false then mode is not block in header`() {
        this.spring.register(XssProtectionBlockFalseConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1") }
        }
    }

    @EnableWebSecurity
    open class XssProtectionBlockFalseConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection {
                        block = false
                    }
                }
            }
        }
    }

    @Test
    fun `headers when XSS protection disabled then X-XSS-Protection header is 0`() {
        this.spring.register(XssProtectionDisabledConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0") }
        }
    }

    @EnableWebSecurity
    open class XssProtectionDisabledConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    xssProtection {
                        xssProtectionEnabled = false
                    }
                }
            }
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

    @EnableWebSecurity
    open class XssProtectionDisabledFunctionConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    xssProtection {
                        disable()
                    }
                }
            }
        }
    }
}
