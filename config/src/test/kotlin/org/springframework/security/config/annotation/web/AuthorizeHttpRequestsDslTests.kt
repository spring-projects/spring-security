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

import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.UnsatisfiedDependencyException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.util.matcher.RegexRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.web.util.WebUtils
import java.util.function.Supplier
import jakarta.servlet.DispatcherType

/**
 * Tests for [AuthorizeHttpRequestsDsl]
 *
 * @author Yuriy Savchenko
 */
@ExtendWith(SpringTestContextExtension::class)
class AuthorizeHttpRequestsDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `request when secured by regex matcher then responds with forbidden`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/private")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Test
    fun `request when allowed by regex matcher then responds with ok`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/path")
            .andExpect {
                status { isOk() }
            }
    }

    @Test
    fun `request when allowed by regex matcher with http method then responds based on method`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.post("/onlyPostPermitted") { with(csrf()) }
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/onlyPostPermitted")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizeHttpRequestsByRegexConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(RegexRequestMatcher("/path", null), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "POST"), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "GET"), denyAll)
                    authorize(RegexRequestMatcher(".*", null), authenticated)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }

            @RequestMapping("/onlyPostPermitted")
            fun onlyPostPermitted() {
            }
        }
    }

    @Test
    fun `request when secured by mvc then responds with forbidden`() {
        this.spring.register(AuthorizeHttpRequestsByMvcConfig::class.java).autowire()

        this.mockMvc.get("/private")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Test
    fun `request when allowed by mvc then responds with OK`() {
        this.spring.register(AuthorizeHttpRequestsByMvcConfig::class.java, LegacyMvcMatchingConfig::class.java).autowire()

        this.mockMvc.get("/path")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/path.html")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/path/")
            .andExpect {
                status { isOk() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeHttpRequestsByMvcConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/path", permitAll)
                    authorize("/**", authenticated)
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

    @Configuration
    open class LegacyMvcMatchingConfig : WebMvcConfigurer {
        override fun configurePathMatch(configurer: PathMatchConfigurer) {
            configurer.setUseSuffixPatternMatch(true)
            configurer.setUseTrailingSlashMatch(true)
        }
    }

    @Test
    fun `request when secured by mvc path variables then responds based on path variable value`() {
        this.spring.register(MvcMatcherPathVariablesConfig::class.java).autowire()

        this.mockMvc.get("/user/user")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/user/deny")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherPathVariablesConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            val access = AuthorizationManager { _: Supplier<Authentication>, context: RequestAuthorizationContext ->
                AuthorizationDecision(context.variables["userName"] == "user")
            }
            http {
                authorizeHttpRequests {
                    authorize("/user/{userName}", access)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/user/{user}")
            fun path(@PathVariable user: String) {
            }
        }
    }

    @Test
    fun `request when user has allowed role then responds with OK`() {
        this.spring.register(HasRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have allowed role then responds with forbidden`() {
        this.spring.register(HasRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasRoleConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasRole("ADMIN"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val adminDetails = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            return InMemoryUserDetailsManager(userDetails, adminDetails)
        }
    }

    @Test
    fun `request when user has some allowed roles then responds with OK`() {
        this.spring.register(HasAnyRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isOk() }
        }

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have any allowed roles then responds with forbidden`() {
        this.spring.register(HasAnyRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("other", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyRoleConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAnyRole("ADMIN", "USER"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val admin1Details = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            val admin2Details = User.withDefaultPasswordEncoder()
                .username("other")
                .password("password")
                .roles("OTHER")
                .build()
            return InMemoryUserDetailsManager(userDetails, admin1Details, admin2Details)
        }
    }

    @Test
    fun `request when user has allowed authority then responds with OK`() {
        this.spring.register(HasAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have allowed authority then responds with forbidden`() {
        this.spring.register(HasAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAuthorityConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAuthority("ROLE_ADMIN"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val adminDetails = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            return InMemoryUserDetailsManager(userDetails, adminDetails)
        }
    }

    @Test
    fun `request when user has some allowed authorities then responds with OK`() {
        this.spring.register(HasAnyAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isOk() }
        }

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have any allowed authorities then responds with forbidden`() {
        this.spring.register(HasAnyAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("other", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyAuthorityConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAnyAuthority("ROLE_ADMIN", "ROLE_USER"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .authorities("ROLE_USER")
                .build()
            val admin1Details = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .authorities("ROLE_ADMIN")
                .build()
            val admin2Details = User.withDefaultPasswordEncoder()
                .username("other")
                .password("password")
                .authorities("ROLE_OTHER")
                .build()
            return InMemoryUserDetailsManager(userDetails, admin1Details, admin2Details)
        }
    }

    @Test
    fun `request when secured by mvc with servlet path then responds based on servlet path`() {
        this.spring.register(MvcMatcherServletPathConfig::class.java).autowire()

        this.mockMvc.perform(get("/spring/path")
            .with { request ->
                request.servletPath = "/spring"
                request
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(get("/other/path")
            .with { request ->
                request.servletPath = "/other"
                request
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/path", "/spring", denyAll)
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
    fun `request when secured by mvc with http method then responds based on http method`() {
        this.spring.register(AuthorizeRequestsByMvcConfigWithHttpMethod::class.java).autowire()

        this.mockMvc.get("/path")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.put("/path") { with(csrf()) }
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeRequestsByMvcConfigWithHttpMethod {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(HttpMethod.GET, "/path", permitAll)
                    authorize(HttpMethod.PUT, "/path", denyAll)
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
    fun `request when secured by mvc with servlet path and http method then responds based on path and method`() {
        this.spring.register(MvcMatcherServletPathHttpMethodConfig::class.java).autowire()

        this.mockMvc.perform(get("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(put("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                    csrf()
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(get("/other/path")
            .with { request ->
                request.apply {
                    servletPath = "/other"
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathHttpMethodConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(HttpMethod.GET, "/path", "/spring", denyAll)
                    authorize(HttpMethod.PUT, "/path", "/spring", denyAll)
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
    fun `request when both authorizeRequests and authorizeHttpRequests configured then exception`() {
        assertThatThrownBy { this.spring.register(BothAuthorizeRequestsConfig::class.java).autowire() }
            .isInstanceOf(UnsatisfiedDependencyException::class.java)
            .hasRootCauseInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining(
                "authorizeHttpRequests cannot be used in conjunction with authorizeRequests. Please select just one."
            )
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class BothAuthorizeRequestsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, permitAll)
                }
                authorizeHttpRequests {
                    authorize(anyRequest, denyAll)
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when shouldFilterAllDispatcherTypes and denyAll and ERROR then responds with forbidden`() {
        this.spring.register(ShouldFilterAllDispatcherTypesTrueDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesTrueDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    shouldFilterAllDispatcherTypes = true
                    authorize(anyRequest, denyAll)
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
    fun `request when shouldFilterAllDispatcherTypes and permitAll and ERROR then responds with ok`() {
        this.spring.register(ShouldFilterAllDispatcherTypesTruePermitAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isOk)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesTruePermitAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    shouldFilterAllDispatcherTypes = true
                    authorize(anyRequest, permitAll)
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
    fun `request when shouldFilterAllDispatcherTypes false and ERROR dispatcher then responds with ok`() {
        this.spring.register(ShouldFilterAllDispatcherTypesFalseAndDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isOk)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesFalseAndDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    shouldFilterAllDispatcherTypes = false
                    authorize(anyRequest, denyAll)
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
    fun `request when shouldFilterAllDispatcherTypes omitted and ERROR dispatcher then responds with forbidden`() {
        this.spring.register(ShouldFilterAllDispatcherTypesOmittedAndDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesOmittedAndDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, denyAll)
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
}
