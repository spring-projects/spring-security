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
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [ContentTypeOptionsDsl]
 *
 * @author Eleftheria Stein
 */
class ContentTypeOptionsDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when content type options configured then X-Content-Type-Options header in response`() {
        this.spring.register(ContentTypeOptionsConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff") }
                }
    }

    @EnableWebSecurity
    open class ContentTypeOptionsConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    contentTypeOptions { }
                }
            }
        }
    }

    @Test
    fun `headers when content type options disabled then X-Content-Type-Options header not in response`() {
        this.spring.register(ContentTypeOptionsDisabledConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { doesNotExist(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS) }
                }
    }

    @EnableWebSecurity
    open class ContentTypeOptionsDisabledConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    contentTypeOptions {
                        disable()
                    }
                }
            }
        }
    }
}
