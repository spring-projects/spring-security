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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders

/**
 * Tests for [SessionFixationDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class SessionFixationDslTests {
    @JvmField
    var spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `session fixation when strategy is new session then new session created and attributes are not preserved`() {
        this.spring.register(NewSessionConfig::class.java, UserDetailsConfig::class.java).autowire()
        val givenSession = MockHttpSession()
        val givenSessionId = givenSession.id
        givenSession.clearAttributes()
        givenSession.setAttribute("name", "value")

        val result = this.mockMvc.perform(MockMvcRequestBuilders.get("/")
                .with(httpBasic("user", "password"))
                .session(givenSession))
                .andReturn()

        val resultingSession = result.request.getSession(false)
        assertThat(resultingSession).isNotEqualTo(givenSession)
        assertThat(resultingSession!!.id).isNotEqualTo(givenSessionId)
        assertThat(resultingSession.getAttribute("name")).isNull()
    }

    @Configuration
    @EnableWebSecurity
    open class NewSessionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    requireExplicitAuthenticationStrategy = false
                    sessionFixation {
                        newSession()
                    }
                }
                httpBasic { }
            }
            return http.build()
        }
    }

    @Test
    fun `session fixation when strategy is migrate session then new session created and attributes are preserved`() {
        this.spring.register(MigrateSessionConfig::class.java, UserDetailsConfig::class.java).autowire()
        val givenSession = MockHttpSession()
        val givenSessionId = givenSession.id
        givenSession.clearAttributes()
        givenSession.setAttribute("name", "value")

        val result = this.mockMvc.perform(MockMvcRequestBuilders.get("/")
                .with(httpBasic("user", "password"))
                .session(givenSession))
                .andReturn()

        val resultingSession = result.request.getSession(false)
        assertThat(resultingSession).isNotEqualTo(givenSession)
        assertThat(resultingSession!!.id).isNotEqualTo(givenSessionId)
        assertThat(resultingSession.getAttribute("name")).isEqualTo("value")
    }

    @Configuration
    @EnableWebSecurity
    open class MigrateSessionConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    requireExplicitAuthenticationStrategy = false
                    sessionFixation {
                        migrateSession()
                    }
                }
                httpBasic { }
            }
            return http.build()
        }
    }

    @Test
    fun `session fixation when strategy is change session id then session id changes and attributes preserved`() {
        this.spring.register(ChangeSessionIdConfig::class.java, UserDetailsConfig::class.java).autowire()
        val givenSession = MockHttpSession()
        val givenSessionId = givenSession.id
        givenSession.clearAttributes()
        givenSession.setAttribute("name", "value")

        val result = this.mockMvc.perform(MockMvcRequestBuilders.get("/")
                .with(httpBasic("user", "password"))
                .session(givenSession))
                .andReturn()

        val resultingSession = result.request.getSession(false)
        assertThat(resultingSession).isEqualTo(givenSession)
        assertThat(resultingSession!!.id).isNotEqualTo(givenSessionId)
        assertThat(resultingSession.getAttribute("name")).isEqualTo("value")
    }

    @Configuration
    @EnableWebSecurity
    open class ChangeSessionIdConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    requireExplicitAuthenticationStrategy = false
                    sessionFixation {
                        changeSessionId()
                    }
                }
                httpBasic { }
            }
            return http.build()
        }
    }

    @Test
    fun `session fixation when strategy is none then session does not change`() {
        this.spring.register(NoneConfig::class.java, UserDetailsConfig::class.java).autowire()
        val givenSession = MockHttpSession()
        val givenSessionId = givenSession.id
        givenSession.clearAttributes()
        givenSession.setAttribute("name", "value")

        val result = this.mockMvc.perform(MockMvcRequestBuilders.get("/")
                .with(httpBasic("user", "password"))
                .session(givenSession))
                .andReturn()

        val resultingSession = result.request.getSession(false)
        assertThat(resultingSession).isEqualTo(givenSession)
        assertThat(resultingSession!!.id).isEqualTo(givenSessionId)
        assertThat(resultingSession.getAttribute("name")).isEqualTo("value")
    }

    @Configuration
    @EnableWebSecurity
    open class NoneConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                sessionManagement {
                    sessionFixation {
                        none()
                    }
                }
                httpBasic { }
            }
            return http.build()
        }
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
