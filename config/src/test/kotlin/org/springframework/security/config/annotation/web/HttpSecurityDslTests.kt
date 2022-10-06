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

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.TestingAuthenticationProvider
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import jakarta.servlet.Filter

/**
 * Tests for [HttpSecurityDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class HttpSecurityDslTests {
    @JvmField
    val spring = SpringTestContext(this)

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
                string(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0")
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultSecurityConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            return http.build()
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

    @ParameterizedTest
    @ValueSource(classes = [
        SecurityRequestMatcherRequestsConfig::class,
        SecurityRequestMatcherHttpRequestsConfig::class
    ])
    fun `request when it does not match the security request matcher then the security rules do not apply`(config: Class<*>) {
        this.spring.register(config).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isNotFound() }
                }
    }

    @ParameterizedTest
    @ValueSource(classes = [
        SecurityRequestMatcherRequestsConfig::class,
        SecurityRequestMatcherHttpRequestsConfig::class
    ])
    fun `request when it matches the security request matcher then the security rules apply`(config: Class<*>) {
        this.spring.register(config).autowire()

        this.mockMvc.get("/path")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class SecurityRequestMatcherRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher(RegexRequestMatcher("/path", null))
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    open class SecurityRequestMatcherHttpRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher(RegexRequestMatcher("/path", null))
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @ParameterizedTest
    @ValueSource(classes = [
        SecurityPatternMatcherRequestsConfig::class,
        SecurityPatternMatcherHttpRequestsConfig::class
    ])
    fun `request when it does not match the security pattern matcher then the security rules do not apply`(config: Class<*>) {
        this.spring.register(config).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isNotFound() }
                }
    }

    @ParameterizedTest
    @ValueSource(classes = [
        SecurityPatternMatcherRequestsConfig::class,
        SecurityPatternMatcherHttpRequestsConfig::class
    ])
    fun `request when it matches the security pattern matcher then the security rules apply`(config: Class<*>) {
        this.spring.register(config).autowire()

        this.mockMvc.get("/path")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class SecurityPatternMatcherRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher("/path")
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class SecurityPatternMatcherHttpRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher("/path")
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @ParameterizedTest
    @ValueSource(classes = [
        MultiMatcherRequestsConfig::class,
        MultiMatcherHttpRequestsConfig::class
    ])
    fun `security pattern matcher when used with security request matcher then both apply`(config: Class<*>) {
        this.spring.register(config).autowire()

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

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MultiMatcherRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher("/path1")
                securityMatcher(RegexRequestMatcher("/path2", null))
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MultiMatcherHttpRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                securityMatcher("/path1")
                securityMatcher(RegexRequestMatcher("/path2", null))
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @ParameterizedTest
    @ValueSource(classes = [
        AuthenticationManagerRequestsConfig::class,
        AuthenticationManagerHttpRequestsConfig::class
    ])
    fun `authentication manager when configured in DSL then used`(config: Class<*>) {
        this.spring.register(config).autowire()
        mockkObject(AuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        every {
            AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any())
        } returns TestingAuthenticationToken("user", "test", "ROLE_USER")
        val request = MockMvcRequestBuilders.get("/")
            .with(httpBasic("user", "password"))
        this.mockMvc.perform(request)
        verify(exactly = 1) { AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()) }
    }

    object AuthenticationManagerConfig {
        val AUTHENTICATION_MANAGER: AuthenticationManager = ProviderManager(TestingAuthenticationProvider())
    }

    @Configuration
    @EnableWebSecurity
    open class AuthenticationManagerRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authenticationManager = AuthenticationManagerConfig.AUTHENTICATION_MANAGER
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                httpBasic { }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthenticationManagerHttpRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authenticationManager = AuthenticationManagerConfig.AUTHENTICATION_MANAGER
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
                httpBasic { }
            }
            return http.build()
        }
    }

    @Test
    fun `HTTP security when custom filter configured then custom filter added to filter chain`() {
        this.spring.register(CustomFilterConfig::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Filter> = filterChain.getFilters("/")

        assertThat(filters).anyMatch { it is CustomFilter }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterAt(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
            }
            return http.build()
        }
    }

    @Test
    fun `HTTP security when custom filter configured with reified variant then custom filter added to filter chain`() {
        this.spring.register(CustomFilterConfigReified::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filters: List<Filter> = filterChain.getFilters("/")

        assertThat(filters).anyMatch { it is CustomFilter }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterConfigReified {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterAt<UsernamePasswordAuthenticationFilter>(CustomFilter())
            }
            return http.build()
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

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterAfterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterAfter(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
                formLogin {}
            }
            return http.build()
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

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterAfterConfigReified{
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterAfter<UsernamePasswordAuthenticationFilter>(CustomFilter())
                formLogin { }
            }
            return http.build()
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

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterBeforeConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterBefore(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
                formLogin {}
            }
            return http.build()
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

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomFilterBeforeConfigReified{
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                addFilterBefore<UsernamePasswordAuthenticationFilter>(CustomFilter())
                formLogin { }
            }
            return http.build()
        }
    }

    class CustomFilter : UsernamePasswordAuthenticationFilter()

    @Test
    fun `HTTP security when apply custom security configurer then custom filter added to filter chain`() {
        this.spring.register(CustomSecurityConfigurerConfig::class.java).autowire()

        val filterChain = spring.context.getBean(FilterChainProxy::class.java)
        val filterClasses: List<Class<out Filter>> = filterChain.getFilters("/").map { it.javaClass }

        assertThat(filterClasses).contains(
            CustomFilter::class.java
        )
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class CustomSecurityConfigurerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                apply(CustomSecurityConfigurer<HttpSecurity>()) {
                    filter = CustomFilter()
                }
            }
            return http.build()
        }
    }

    class CustomSecurityConfigurer<H : HttpSecurityBuilder<H>> : AbstractHttpConfigurer<CustomSecurityConfigurer<H>, H>() {
        var filter: Filter? = null
        override fun init(builder: H) {
            filter = filter ?: UsernamePasswordAuthenticationFilter()
        }

        override fun configure(builder: H) {
            builder.addFilterBefore(CustomFilter(), UsernamePasswordAuthenticationFilter::class.java)
        }
    }
}
