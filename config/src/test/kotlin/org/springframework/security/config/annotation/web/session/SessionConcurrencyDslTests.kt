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

package org.springframework.security.config.annotation.web.session

import io.mockk.every
import io.mockk.mockkObject
import java.util.Date
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.session.SessionInformation
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * Tests for [SessionConcurrencyDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class SessionConcurrencyDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `session concurrency when maximum sessions then no more sessions allowed`() {
        this.spring.register(MaximumSessionsConfig::class.java, UserDetailsConfig::class.java).autowire()

        this.mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", "user")
                .param("password", "password"))

        this.mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", "user")
                .param("password", "password"))
                .andExpect(status().isFound)
                .andExpect(redirectedUrl("/login?error"))
    }

    @Configuration
    @EnableWebSecurity
    open class MaximumSessionsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    sessionConcurrency {
                        maximumSessions = 1
                        maxSessionsPreventsLogin = true
                    }
                }
                formLogin { }
            }
            return http.build()
        }
    }

    @Test
    fun `session concurrency when expired url then redirects to url`() {
        this.spring.register(ExpiredUrlConfig::class.java).autowire()
        mockkObject(ExpiredUrlConfig.SESSION_REGISTRY)

        val session = MockHttpSession()
        val sessionInformation = SessionInformation("", session.id, Date(0))
        sessionInformation.expireNow()
        every { ExpiredUrlConfig.SESSION_REGISTRY.getSessionInformation(any()) } returns sessionInformation

        this.mockMvc.perform(get("/").session(session))
                .andExpect(redirectedUrl("/expired-session"))
    }

    @Configuration
    @EnableWebSecurity
    open class ExpiredUrlConfig {

        companion object {
            val SESSION_REGISTRY: SessionRegistry = SessionRegistryImpl()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    sessionConcurrency {
                        maximumSessions = 1
                        expiredUrl = "/expired-session"
                        sessionRegistry = SESSION_REGISTRY
                    }
                }
            }
            return http.build()
        }

        @Bean
        open fun sessionRegistry(): SessionRegistry = SESSION_REGISTRY
    }

    @Test
    fun `session concurrency when expired session strategy then strategy used`() {
        this.spring.register(ExpiredSessionStrategyConfig::class.java).autowire()
        mockkObject(ExpiredSessionStrategyConfig.SESSION_REGISTRY)

        val session = MockHttpSession()
        val sessionInformation = SessionInformation("", session.id, Date(0))
        sessionInformation.expireNow()
        every { ExpiredSessionStrategyConfig.SESSION_REGISTRY.getSessionInformation(any()) } returns sessionInformation

        this.mockMvc.perform(get("/").session(session))
                .andExpect(redirectedUrl("/expired-session"))
    }

    @Configuration
    @EnableWebSecurity
    open class ExpiredSessionStrategyConfig {

        companion object {
            val SESSION_REGISTRY: SessionRegistry = SessionRegistryImpl()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    sessionConcurrency {
                        maximumSessions = 1
                        expiredSessionStrategy = SimpleRedirectSessionInformationExpiredStrategy("/expired-session")
                        sessionRegistry = SESSION_REGISTRY
                    }
                }
            }
            return http.build()
        }

        @Bean
        open fun sessionRegistry(): SessionRegistry = SESSION_REGISTRY
    }

    @Configuration
    open class UserDetailsConfig {
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
