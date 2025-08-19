/*
 * Copyright 2004-present the original author or authors.
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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import java.net.URI
import java.util.*

/**
 * Tests for [HttpsRedirectDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class HttpsRedirectDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `request when matches redirect to HTTPS matcher then redirects to HTTPS`() {
        this.spring.register(HttpRedirectMatcherConfig::class.java, UsePathPatternConfig::class.java).autowire()

        val result = this.mockMvc.get("/secure")
            .andExpect {
                status { is3xxRedirection() }
            }.andReturn()

        val location = result.response.getHeader(HttpHeaders.LOCATION)?.let { URI.create(it) }
        assertThat(location?.scheme).isEqualTo("https")
    }

    @Test
    fun `request when does not match redirect to HTTPS matcher then does not redirect`() {
        this.spring.register(HttpRedirectMatcherConfig::class.java, UsePathPatternConfig::class.java).autowire()

        this.mockMvc.get("/")
            .andExpect {
                status { isNotFound() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HttpRedirectMatcherConfig {
        @Bean
        open fun springFilterChain(http: HttpSecurity, path: PathPatternRequestMatcher.Builder): SecurityFilterChain {
            http {
                redirectToHttps {
                    requestMatchers = arrayOf(path.matcher("/secure"))
                }
            }
            return http.build()
        }
    }

    @Configuration
    open class UsePathPatternConfig {
        @Bean
        open fun requestMatcherBuilder() = PathPatternRequestMatcherBuilderFactoryBean()
    }

    @Test
    fun `request when port mapper configured then redirected to HTTPS port`() {
        this.spring.register(PortMapperConfig::class.java).autowire()

        val result = this.mockMvc.get("http://localhost:543")
            .andExpect {
                status {
                    is3xxRedirection()
                }
            }.andReturn()

        val location = result.response.getHeader(HttpHeaders.LOCATION)?.let { URI.create(it) }
        assertThat(location?.scheme).isEqualTo("https")
        assertThat(location?.port).isEqualTo(123)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class PortMapperConfig {
        @Bean
        open fun springFilterChain(http: HttpSecurity): SecurityFilterChain {
            val customPortMapper = PortMapperImpl()
            customPortMapper.setPortMappings(Collections.singletonMap("543", "123"))
            http {
                portMapper {
                    portMapper = customPortMapper
                }
                redirectToHttps { }
            }
            return http.build()
        }
    }
}
