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
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Tests for [HttpBasicDsl]
 *
 * @author Eleftheria Stein
 */
class HttpBasicDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `http basic when configured then insecure request cannot access`() {
        this.spring.register(HttpBasicConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isUnauthorized }
                }
    }

    @Test
    fun `http basic when configured then response includes basic challenge`() {
        this.spring.register(HttpBasicConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string("WWW-Authenticate", "Basic realm=\"Realm\"") }
                }
    }

    @Test
    fun `http basic when valid user then permitted`() {
        this.spring.register(HttpBasicConfig::class.java, UserConfig::class.java, MainController::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isOk }
        }
    }

    @EnableWebSecurity
    open class HttpBasicConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                httpBasic {}
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun httpBasicWhenCustomRealmThenUsed() {
        this.spring.register(CustomRealmConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    header { string("WWW-Authenticate", "Basic realm=\"Custom Realm\"") }
                }
    }

    @EnableWebSecurity
    open class CustomRealmConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                httpBasic {
                    realmName = "Custom Realm"
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `http basic when custom authentication entry point then used`() {
        this.spring.register(CustomAuthenticationEntryPointConfig::class.java).autowire()

        this.mockMvc.get("/")

        verify<AuthenticationEntryPoint>(CustomAuthenticationEntryPointConfig.ENTRY_POINT)
                .commence(any(HttpServletRequest::class.java),
                        any(HttpServletResponse::class.java),
                        any(AuthenticationException::class.java))
    }

    @EnableWebSecurity
    open class CustomAuthenticationEntryPointConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var ENTRY_POINT: AuthenticationEntryPoint = mock(AuthenticationEntryPoint::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                httpBasic {
                    authenticationEntryPoint = ENTRY_POINT
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
    }

    @Test
    fun `http basic when custom authentication details source then used`() {
        this.spring.register(CustomAuthenticationDetailsSourceConfig::class.java,
                UserConfig::class.java, MainController::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("username", "password"))
        }

        verify(CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE)
                .buildDetails(any(HttpServletRequest::class.java))
    }

    @EnableWebSecurity
    open class CustomAuthenticationDetailsSourceConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var AUTHENTICATION_DETAILS_SOURCE = mock(AuthenticationDetailsSource::class.java) as AuthenticationDetailsSource<HttpServletRequest, *>
        }

        override fun configure(http: HttpSecurity) {
            http {
                httpBasic {
                    authenticationDetailsSource = AUTHENTICATION_DETAILS_SOURCE
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
        }
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

    @RestController
    class MainController {
        @GetMapping("/")
        fun main() {
        }
    }
}
