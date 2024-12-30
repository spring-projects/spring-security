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
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationException
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * Tests for [SessionManagementDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class SessionManagementDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `session management when invalid session url then redirected to url`() {
        this.spring.register(InvalidSessionUrlConfig::class.java).autowire()

        this.mockMvc.perform(get("/")
            .with { request ->
                request.isRequestedSessionIdValid = false
                request.requestedSessionId = "id"
                request
            })
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/invalid"))
    }

    @Configuration
    @EnableWebSecurity
    open class InvalidSessionUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    invalidSessionUrl = "/invalid"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `session management when invalid session strategy then strategy used`() {
        this.spring.register(InvalidSessionStrategyConfig::class.java).autowire()

        this.mockMvc.perform(get("/")
            .with { request ->
                request.isRequestedSessionIdValid = false
                request.requestedSessionId = "id"
                request
            })
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/invalid"))
    }

    @Configuration
    @EnableWebSecurity
    open class InvalidSessionStrategyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    invalidSessionStrategy = SimpleRedirectInvalidSessionStrategy("/invalid")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `session management when session authentication error url then redirected to url`() {
        this.spring.register(SessionAuthenticationErrorUrlConfig::class.java).autowire()
        val authentication: Authentication = TestingAuthenticationToken("user", "password", "ROLE_USER")
        val session: MockHttpSession = mockk(relaxed = true)
        every { session.changeSessionId() } throws SessionAuthenticationException("any SessionAuthenticationException")
        every<Any?> { session.getAttribute(any()) } returns null

        this.mockMvc.perform(get("/")
            .with(authentication(authentication))
            .session(session))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/session-auth-error"))
    }

    @Configuration
    @EnableWebSecurity
    open class SessionAuthenticationErrorUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                sessionManagement {
                    sessionAuthenticationErrorUrl = "/session-auth-error"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `session management when session authentication failure handler then handler used`() {
        this.spring.register(SessionAuthenticationFailureHandlerConfig::class.java).autowire()
        val authentication: Authentication = TestingAuthenticationToken("user", "password", "ROLE_USER")
        val session: MockHttpSession = mockk(relaxed = true)
        every { session.changeSessionId() } throws SessionAuthenticationException("any SessionAuthenticationException")
        every<Any?> { session.getAttribute(any()) } returns null

        this.mockMvc.perform(get("/")
            .with(authentication(authentication))
            .session(session))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/session-auth-error"))
    }

    @Configuration
    @EnableWebSecurity
    open class SessionAuthenticationFailureHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                sessionManagement {
                    sessionAuthenticationFailureHandler = SimpleUrlAuthenticationFailureHandler("/session-auth-error")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `session management when stateless policy then does not store session`() {
        this.spring.register(StatelessSessionManagementConfig::class.java).autowire()

        val result = this.mockMvc.perform(get("/"))
            .andReturn()

        assertThat(result.request.getSession(false)).isNull()
    }

    @Configuration
    @EnableWebSecurity
    open class StatelessSessionManagementConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                sessionManagement {
                    sessionCreationPolicy = SessionCreationPolicy.STATELESS
                }
            }
            return http.build()
        }
    }

    @Test
    fun `session management when session authentication strategy then strategy used`() {
        this.spring.register(SessionAuthenticationStrategyConfig::class.java).autowire()
        mockkObject(SessionAuthenticationStrategyConfig.STRATEGY)
        val authentication: Authentication = TestingAuthenticationToken("user", "password", "ROLE_USER")
        val session: MockHttpSession = mockk(relaxed = true)
        every { session.changeSessionId() } throws SessionAuthenticationException("any SessionAuthenticationException")
        every<Any?> { session.getAttribute(any()) } returns null
        justRun {  SessionAuthenticationStrategyConfig.STRATEGY.onAuthentication(any(), any(), any()) }

        this.mockMvc.perform(get("/")
            .with(authentication(authentication))
            .session(session))

        verify(exactly = 1) { SessionAuthenticationStrategyConfig.STRATEGY.onAuthentication(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class SessionAuthenticationStrategyConfig {

        companion object {
            val STRATEGY: SessionAuthenticationStrategy = NullAuthenticatedSessionStrategy()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                sessionManagement {
                    sessionAuthenticationStrategy = STRATEGY
                }
            }
            return http.build()
        }

        @Bean
        open fun sessionAuthenticationStrategy(): SessionAuthenticationStrategy = STRATEGY
    }
}
