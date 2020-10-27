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
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.util.matcher.RegexRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 * Tests for [AuthorizeRequestsDsl]
 *
 * @author Eleftheria Stein
 */
class AuthorizeRequestsDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `request when secured by regex matcher then responds with forbidden`() {
        this.spring.register(AuthorizeRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/private")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Test
    fun `request when allowed by regex matcher then responds with ok`() {
        this.spring.register(AuthorizeRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/path")
                .andExpect {
                    status { isOk() }
                }
    }

    @Test
    fun `request when allowed by regex matcher with http method then responds based on method`() {
        this.spring.register(AuthorizeRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.post("/onlyPostPermitted") { with(csrf()) }
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/onlyPostPermitted")
            .andExpect {
                status { isForbidden() }
            }
    }

    @EnableWebSecurity
    open class AuthorizeRequestsByRegexConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(RegexRequestMatcher("/path", null), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "POST"), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "GET"), denyAll)
                    authorize(RegexRequestMatcher(".*", null), authenticated)
                }
            }
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
        this.spring.register(AuthorizeRequestsByMvcConfig::class.java).autowire()

        this.mockMvc.get("/private")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Test
    fun `request when allowed by mvc then responds with OK`() {
        this.spring.register(AuthorizeRequestsByMvcConfig::class.java, LegacyMvcMatchingConfig::class.java).autowire()

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

    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeRequestsByMvcConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/path", permitAll)
                    authorize("/**", authenticated)
                }
            }
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

    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherPathVariablesConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/user/{userName}", "#userName == 'user'")
                }
            }
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

    @EnableWebSecurity
    @EnableWebMvc
    open class HasRoleConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/**", hasRole("ADMIN"))
                }
                httpBasic { }
            }
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
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

    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyRoleConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/**", hasAnyRole("ADMIN", "USER"))
                }
                httpBasic { }
            }
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
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

    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyAuthorityConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/**", hasAnyAuthority("ROLE_ADMIN", "ROLE_USER"))
                }
                httpBasic { }
            }
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index() {
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
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

        this.mockMvc.perform(MockMvcRequestBuilders.get("/spring/path")
                .with { request ->
                    request.servletPath = "/spring"
                    request
                })
                .andExpect(status().isForbidden)

        this.mockMvc.perform(MockMvcRequestBuilders.get("/other/path")
                .with { request ->
                    request.servletPath = "/other"
                    request
                })
                .andExpect(status().isOk)
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize("/path",
                            "/spring",
                            denyAll)
                }
            }
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeRequestsByMvcConfigWithHttpMethod : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(HttpMethod.GET, "/path", permitAll)
                    authorize(HttpMethod.PUT, "/path", denyAll)
                }
            }
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

    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathHttpMethodConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(HttpMethod.GET, "/path", "/spring", denyAll)
                    authorize(HttpMethod.PUT, "/path", "/spring", denyAll)
                }
            }
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
        this.spring.register(MvcMatcherServletPathConfig::class.java).autowire()

        this.mockMvc.perform(MockMvcRequestBuilders.get("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(MockMvcRequestBuilders.put("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                    csrf()
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(MockMvcRequestBuilders.get("/other/path")
            .with { request ->
                request.apply {
                    servletPath = "/other"
                }
            })
            .andExpect(status().isOk)
    }
}
