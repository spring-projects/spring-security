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
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.savedrequest.NullRequestCache
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl

/**
 * Tests for [RequestCacheDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class RequestCacheDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `GET when request cache enabled then redirected to cached page`() {
        this.spring.register(RequestCacheConfig::class.java).autowire()

        this.mockMvc.get("/test")

        this.mockMvc.perform(formLogin())
                .andExpect {
                    redirectedUrl("http://localhost/test")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class RequestCacheConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requestCache { }
                formLogin { }
            }
            return http.build()
        }
    }

    @Test
    fun `GET when custom request cache then custom request cache used`() {
        this.spring.register(CustomRequestCacheConfig::class.java).autowire()

        this.mockMvc.get("/test")

        this.mockMvc.perform(formLogin())
                .andExpect {
                    redirectedUrl("/")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomRequestCacheConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requestCache {
                    requestCache = NullRequestCache()
                }
                formLogin { }
            }
            return http.build()
        }
    }
}
