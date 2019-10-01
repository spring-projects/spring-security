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

package org.springframework.security.config.web.servlet

import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.PortMapperImpl
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.util.*

/**
 * Tests for [PortMapperDsl]
 *
 * @author Eleftheria Stein
 */
class PortMapperDslTests  {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `port mapper when specifying map then redirects to https port`() {
        this.spring.register(PortMapperMapConfig::class.java).autowire()

        this.mockMvc.get("http://localhost:543")
                .andExpect {
                    redirectedUrl("https://localhost:123")
                }
    }

    @EnableWebSecurity
    open class PortMapperMapConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                requiresChannel {
                    secure(anyRequest, requiresSecure)
                }
                portMapper {
                    map(543, 123)
                }
            }
        }
    }

    @Test
    fun `port mapper when specifying custom mapper then redirects to https port`() {
        this.spring.register(CustomPortMapperConfig::class.java).autowire()

        this.mockMvc.get("http://localhost:543")
                .andExpect {
                    redirectedUrl("https://localhost:123")
                }
    }

    @EnableWebSecurity
    open class CustomPortMapperConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            val customPortMapper = PortMapperImpl()
            customPortMapper.setPortMappings(Collections.singletonMap("543", "123"))
            http {
                requiresChannel {
                    secure(anyRequest, requiresSecure)
                }
                portMapper {
                    portMapper = customPortMapper
                }
            }
        }
    }
}
