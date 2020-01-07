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
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [ContentSecurityPolicyDsl]
 *
 * @author Eleftheria Stein
 */
class ContentSecurityPolicyDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when content security policy configured then header in response`() {
        this.spring.register(ContentSecurityPolicyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, "default-src 'self'") }
        }
    }

    @EnableWebSecurity
    open class ContentSecurityPolicyConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy { }
                }
            }
        }
    }

    @Test
    fun `headers when content security policy configured with custom policy directives then custom directives in header`() {
        this.spring.register(CustomPolicyDirectivesConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, "default-src 'self'; script-src trustedscripts.example.com") }
        }
    }

    @EnableWebSecurity
    open class CustomPolicyDirectivesConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        policyDirectives = "default-src 'self'; script-src trustedscripts.example.com"
                    }
                }
            }
        }
    }

    @Test
    fun `headers when report only content security policy report only header in response`() {
        this.spring.register(ReportOnlyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY_REPORT_ONLY, "default-src 'self'") }
        }
    }

    @EnableWebSecurity
    open class ReportOnlyConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    contentSecurityPolicy {
                        reportOnly = true
                    }
                }
            }
        }
    }
}
