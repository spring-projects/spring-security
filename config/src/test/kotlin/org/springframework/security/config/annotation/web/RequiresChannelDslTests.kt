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

import io.mockk.mockkObject
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.channel.ChannelProcessor
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 * Tests for [RequiresChannelDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class RequiresChannelDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `requires channel when requires secure then redirects to https`() {
        this.spring.register(RequiresSecureConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    redirectedUrl("https://localhost/")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class RequiresSecureConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requiresChannel {
                    secure(anyRequest, requiresSecure)
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when channel matches mvc with servlet path then redirects based on servlet path`() {
        this.spring.register(MvcMatcherServletPathConfig::class.java).autowire()

        this.mockMvc.perform(MockMvcRequestBuilders.get("/spring/path")
                .with { request ->
                    request.servletPath = "/spring"
                    request
                })
                .andExpect(status().isFound)
                .andExpect(redirectedUrl("https://localhost/spring/path"))

        this.mockMvc.perform(MockMvcRequestBuilders.get("/other/path")
                .with { request ->
                    request.servletPath = "/other"
                    request
                })
                .andExpect(MockMvcResultMatchers.status().isOk)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requiresChannel {
                    secure("/path",
                            "/spring",
                            requiresSecure)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `requires channel when channel processors configured then channel processors used`() {
        this.spring.register(ChannelProcessorsConfig::class.java).autowire()
        mockkObject(ChannelProcessorsConfig.CHANNEL_PROCESSOR)

        this.mockMvc.get("/")

        verify(exactly = 0) {  ChannelProcessorsConfig.CHANNEL_PROCESSOR.supports(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class ChannelProcessorsConfig {

        companion object {
            val CHANNEL_PROCESSOR: ChannelProcessor = object : ChannelProcessor {
                override fun decide(invocation: FilterInvocation?, config: MutableCollection<ConfigAttribute>?) {}
                override fun supports(attribute: ConfigAttribute?): Boolean = true
            }
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                requiresChannel {
                    channelProcessors = listOf(CHANNEL_PROCESSOR)
                    secure(anyRequest, requiresSecure)
                }
            }
            return http.build()
        }
    }
}
