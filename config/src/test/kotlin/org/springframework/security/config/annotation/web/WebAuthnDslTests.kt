/*
 * Copyright 2002-2025 the original author or authors.
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

import org.hamcrest.Matchers
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers

/**
 * Tests for [WebAuthnDsl]
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension::class)
class WebAuthnDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `default configuration`() {
        this.spring.register(WebauthnConfig::class.java).autowire()

        this.mockMvc.post("/test1")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Test
    fun `webauthn and formLogin configured with default registration page`() {
        spring.register(DefaultWebauthnConfig::class.java).autowire()

        this.mockMvc.get("/login/webauthn.js")
                .andExpect {
                    MockMvcResultMatchers.status().isOk
                    header {
                        string("content-type", "text/javascript;charset=UTF-8")
                    }
                    content {
                        string(Matchers.containsString("async function authenticate("))
                    }
                }
    }

    @Test
    fun `webauthn and formLogin configured with disabled default registration page`() {
        spring.register(FormLoginAndNoDefaultRegistrationPageConfiguration::class.java).autowire()

        this.mockMvc.get("/login/webauthn.js")
                .andExpect {
                    MockMvcResultMatchers.status().isOk
                    header {
                        string("content-type", "text/javascript;charset=UTF-8")
                    }
                    content {
                        string(Matchers.containsString("async function authenticate("))
                    }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class FormLoginAndNoDefaultRegistrationPageConfiguration {
        @Bean
        open fun userDetailsService(): UserDetailsService  =
                InMemoryUserDetailsManager()


        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http{
                formLogin { }
                webAuthn {
                    disableDefaultRegistrationPage = true
                }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultWebauthnConfig {
        @Bean
        open fun userDetailsService(): UserDetailsService  =
                InMemoryUserDetailsManager()


        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http{
                formLogin { }
                webAuthn { }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    open class WebauthnConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                webAuthn {
                    rpName = "Spring Security Relying Party"
                    rpId = "example.com"
                    allowedOrigins = setOf("https://example.com")
                }
            }
            return http.build()
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("rod")
                .password("password")
                .roles("USER")
                .build()
            return InMemoryUserDetailsManager(userDetails)
        }
    }
}
