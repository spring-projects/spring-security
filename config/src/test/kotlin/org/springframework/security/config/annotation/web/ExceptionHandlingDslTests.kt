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

import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.User.withUsername
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 * Tests for [ExceptionHandlingDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class ExceptionHandlingDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `request when exception handling enabled then returns forbidden`() {
        this.spring.register(ExceptionHandlingConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isForbidden() }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ExceptionHandlingConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling { }
            }
            return http.build()
        }
    }

    @Test
    fun `request when exception handling disabled then throws exception`() {
        this.spring.register(ExceptionHandlingDisabledConfig::class.java).autowire()

        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            this.mockMvc.get("/")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ExceptionHandlingDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    disable()
                }
            }
            return http.build()
        }
    }

    @Test
    fun `exception handling when custom access denied page then redirects to custom page`() {
        this.spring.register(AccessDeniedPageConfig::class.java).autowire()

        this.mockMvc.get("/admin") {
            with(user(withUsername("user").password("password").roles("USER").build()))
        }.andExpect {
            status { isForbidden() }
            forwardedUrl("/access-denied")
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AccessDeniedPageConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize("/admin", hasAuthority("ROLE_ADMIN"))
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    accessDeniedPage = "/access-denied"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `exception handling when custom access denied handler then handler used`() {
        this.spring.register(AccessDeniedHandlerConfig::class.java).autowire()

        this.mockMvc.get("/admin") {
            with(user(withUsername("user").password("password").roles("USER").build()))
        }.andExpect {
            status { isForbidden() }
            forwardedUrl("/access-denied")
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AccessDeniedHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            val customAccessDeniedHandler = AccessDeniedHandlerImpl()
            customAccessDeniedHandler.setErrorPage("/access-denied")
            http {
                authorizeRequests {
                    authorize("/admin", hasAuthority("ROLE_ADMIN"))
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    accessDeniedHandler = customAccessDeniedHandler
                }
            }
            return http.build()
        }
    }

    @Test
    fun `exception handling when default access denied handler for page then handlers used`() {
        this.spring.register(AccessDeniedHandlerForConfig::class.java).autowire()

        this.mockMvc.get("/admin1") {
            with(user(withUsername("user").password("password").roles("USER").build()))
        }.andExpect {
            status { isForbidden() }
            forwardedUrl("/access-denied1")
        }

        this.mockMvc.get("/admin2") {
            with(user(withUsername("user").password("password").roles("USER").build()))
        }.andExpect {
            status { isForbidden() }
            forwardedUrl("/access-denied2")
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AccessDeniedHandlerForConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            val customAccessDeniedHandler1 = AccessDeniedHandlerImpl()
            customAccessDeniedHandler1.setErrorPage("/access-denied1")
            val customAccessDeniedHandler2 = AccessDeniedHandlerImpl()
            customAccessDeniedHandler2.setErrorPage("/access-denied2")
            http {
                authorizeRequests {
                    authorize("/admin1", hasAuthority("ROLE_ADMIN"))
                    authorize("/admin2", hasAuthority("ROLE_ADMIN"))
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    defaultAccessDeniedHandlerFor(customAccessDeniedHandler1, AntPathRequestMatcher("/admin1"))
                    defaultAccessDeniedHandlerFor(customAccessDeniedHandler2, AntPathRequestMatcher("/admin2"))
                }
            }
            return http.build()
        }
    }

    @Test
    fun `exception handling when custom authentication entry point then entry point used`() {
        this.spring.register(AuthenticationEntryPointConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("http://localhost/custom-login")
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthenticationEntryPointConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    authenticationEntryPoint = LoginUrlAuthenticationEntryPoint("/custom-login")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `exception handling when authentication entry point for page then entry points used`() {
        this.spring.register(AuthenticationEntryPointForConfig::class.java).autowire()

        this.mockMvc.get("/secured1")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("http://localhost/custom-login1")
                }

        this.mockMvc.get("/secured2")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("http://localhost/custom-login2")
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthenticationEntryPointForConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            val customAuthenticationEntryPoint1 = LoginUrlAuthenticationEntryPoint("/custom-login1")
            val customAuthenticationEntryPoint2 = LoginUrlAuthenticationEntryPoint("/custom-login2")
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                exceptionHandling {
                    defaultAuthenticationEntryPointFor(customAuthenticationEntryPoint1, AntPathRequestMatcher("/secured1"))
                    defaultAuthenticationEntryPointFor(customAuthenticationEntryPoint2, AntPathRequestMatcher("/secured2"))
                }
            }
            return http.build()
        }
    }
}
