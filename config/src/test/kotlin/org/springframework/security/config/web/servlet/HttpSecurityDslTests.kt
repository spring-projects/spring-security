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

import org.assertj.core.api.Assertions.assertThat
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter
import org.springframework.security.web.util.matcher.RegexRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import javax.servlet.Filter

/**
 * Tests for [HttpSecurityDsl]
 *
 * @author Eleftheria Stein
 */
class HttpSecurityDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `post when default security configured then CSRF prevents the request`() {
        this.spring.register(DefaultSecurityConfig::class.java).autowire()

        this.mockMvc.post("/")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Test
    fun `when default security configured then default headers are in the response`() {
        this.spring.register(DefaultSecurityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff")
            }
            header {
                string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name)
            }
            header {
                string(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains")
            }
            header {
                string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate")
            }
            header {
                string(HttpHeaders.EXPIRES, "0")
            }
            header {
                string(HttpHeaders.PRAGMA, "no-cache")
            }
            header {
                string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1; mode=block")
            }
        }
    }

    @EnableWebSecurity
    open class DefaultSecurityConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {}
        }

        @Configuration
        open class UserConfig {
            @Bean
            open fun userDetailsService(): UserDetailsService {
                val userDetails = User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build()
                return InMemoryUserDetailsManager(userDetails)
            }
        }
    }

    @Test
    fun `request when it does not match the security request matcher then the security rules do not apply`() {
        this.spring.register(SecurityRequestMatcherConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isNotFound() }
                }
    }

    @Test
    fun `request when it matches the security request matcher then the security rules apply`() {
        this.spring.register(SecurityRequestMatcherConfig::class.java).autowire()

        this.mockMvc.get("/path")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @EnableWebSecurity
    open class SecurityRequestMatcherConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                securityMatcher(RegexRequestMatcher("/path", null))
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `request when it does not match the security pattern matcher then the security rules do not apply`() {
        this.spring.register(SecurityPatternMatcherConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isNotFound() }
                }
    }

    @Test
    fun `request when it matches the security pattern matcher then the security rules apply`() {
        this.spring.register(SecurityPatternMatcherConfig::class.java).autowire()

        this.mockMvc.get("/path")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class SecurityPatternMatcherConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                securityMatcher("/path")
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `security pattern matcher when used with security request matcher then both apply`() {
        this.spring.register(MultiMatcherConfig::class.java).autowire()

        this.mockMvc.get("/path1")
                .andExpect {
                    status { isForbidden() }
                }

        this.mockMvc.get("/path2")
                .andExpect {
                    status { isForbidden() }
                }

        this.mockMvc.get("/path3")
                .andExpect {
                    status { isNotFound() }
                }
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class MultiMatcherConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                securityMatcher("/path1")
                securityMatcher(RegexRequestMatcher("/path2", null))
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured then custom filter added to filter chain`() {
        this.spring.register(CustomFilterConfig::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Filter> = filterChain.getFilters("/")

        assertThat(filters).hasSize(1)
        assertThat(filters[0]).isExactlyInstanceOf(CustomFilter::class.java)
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterConfig : WebSecurityConfigurerAdapter(true) {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterAt(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured with reified variant then custom filter added to filter chain`() {
        this.spring.register(CustomFilterConfigReified::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Filter> = filterChain.getFilters("/")

        assertThat(filters).hasSize(1)
        assertThat(filters[0]).isExactlyInstanceOf(CustomFilter::class.java)
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterConfigReified : WebSecurityConfigurerAdapter(true) {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterAt<UsernamePasswordAuthenticationFilter>(CustomFilter())
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured then custom filter added after specific filter to filter chain`() {
        this.spring.register(CustomFilterAfterConfig::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Class<out Filter>> = filterChain.getFilters("/").map { it.javaClass }

        assertThat(filters).containsSubsequence(
            UsernamePasswordAuthenticationFilter::class.java,
            CustomFilter::class.java
        )
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterAfterConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterAfter(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
                formLogin {}
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured with reified variant then custom filter added after specific filter to filter chain`() {
        this.spring.register(CustomFilterAfterConfigReified::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filterClasses: List<Class<out Filter>> = filterChain.getFilters("/").map { it.javaClass }

        assertThat(filterClasses).containsSubsequence(
            UsernamePasswordAuthenticationFilter::class.java,
            CustomFilter::class.java
        )
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterAfterConfigReified : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterAfter<UsernamePasswordAuthenticationFilter>(CustomFilter())
                formLogin { }
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured then custom filter added before specific filter to filter chain`() {
        this.spring.register(CustomFilterBeforeConfig::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Class<out Filter>> = filterChain.getFilters("/").map { it.javaClass }

        assertThat(filters).containsSubsequence(
            CustomFilter::class.java,
            UsernamePasswordAuthenticationFilter::class.java
        )
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterBeforeConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterBefore(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
                formLogin {}
            }
        }
    }

    @Test
    fun `HTTP security when custom filter configured with reified variant then custom filter added before specific filter to filter chain`() {
        this.spring.register(CustomFilterBeforeConfigReified::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filterClasses: List<Class<out Filter>> = filterChain.getFilters("/").map { it.javaClass }

        assertThat(filterClasses).containsSubsequence(
            CustomFilter::class.java,
            UsernamePasswordAuthenticationFilter::class.java
        )
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterBeforeConfigReified : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                addFilterBefore<UsernamePasswordAuthenticationFilter>(CustomFilter())
                formLogin { }
            }
        }
    }

    class CustomFilter : UsernamePasswordAuthenticationFilter()
}
