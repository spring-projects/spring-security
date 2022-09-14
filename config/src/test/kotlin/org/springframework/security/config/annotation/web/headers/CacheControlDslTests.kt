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
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [CacheControlDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class CacheControlDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when cache control configured then cache control headers in response`() {
        this.spring.register(CacheControlConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate") }
                    header { string(HttpHeaders.EXPIRES, "0") }
                    header { string(HttpHeaders.PRAGMA, "no-cache") }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class CacheControlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    cacheControl { }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when cache control disabled then no cache control headers in response`() {
        this.spring.register(CacheControlDisabledConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { doesNotExist(HttpHeaders.CACHE_CONTROL) }
                    header { doesNotExist(HttpHeaders.EXPIRES) }
                    header { doesNotExist(HttpHeaders.PRAGMA) }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class CacheControlDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    cacheControl {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }
}
