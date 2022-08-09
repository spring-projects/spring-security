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
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.util.*

/**
 * Tests for [PortMapperDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class PortMapperDslTests  {
    @JvmField
    val spring = SpringTestContext(this)

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

    @Configuration
    @EnableWebSecurity
    open class PortMapperMapConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requiresChannel {
                    secure(anyRequest, requiresSecure)
                }
                portMapper {
                    map(543, 123)
                }
            }
            return http.build()
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

    @Configuration
    @EnableWebSecurity
    open class CustomPortMapperConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
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
            return http.build()
        }
    }
}
