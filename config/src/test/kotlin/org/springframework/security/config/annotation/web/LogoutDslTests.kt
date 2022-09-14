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
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
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
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

/**
 * Tests for [LogoutDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class LogoutDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `logout when custom logout url then custom url used`() {
        this.spring.register(CustomLogoutUrlConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomLogoutUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    logoutUrl = "/custom/logout"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when custom logout request matcher then custom request matcher used`() {
        this.spring.register(CustomLogoutRequestMatcherConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomLogoutRequestMatcherConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    logoutRequestMatcher = AntPathRequestMatcher("/custom/logout")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when custom success url then redirects to success url`() {
        this.spring.register(SuccessUrlConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class SuccessUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    logoutSuccessUrl = "/login"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when custom success handler then redirects to success url`() {
        this.spring.register(SuccessHandlerConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class SuccessHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    logoutSuccessHandler = SimpleUrlLogoutSuccessHandler()
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when permit all then logout allowed`() {
        this.spring.register(PermitAllConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class PermitAllConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                logout {
                    logoutUrl = "/custom/logout"
                    permitAll()
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when clear authentication false then authentication not cleared`() {
        this.spring.register(ClearAuthenticationFalseConfig::class.java).autowire()
        val currentContext = SecurityContextHolder.createEmptyContext()
        currentContext.authentication = TestingAuthenticationToken("user", "password", "ROLE_USER")
        val currentSession = MockHttpSession()
        currentSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, currentContext)

        this.mockMvc.post("/logout") {
            with(csrf())
            session = currentSession
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }

        assertThat(currentContext.authentication).isNotNull
    }

    @Configuration
    @EnableWebSecurity
    open class ClearAuthenticationFalseConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    clearAuthentication = false
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when invalidate http session false then session not invalidated`() {
        this.spring.register(InvalidateHttpSessionFalseConfig::class.java).autowire()
        val currentSession = MockHttpSession()

        this.mockMvc.post("/logout") {
            with(csrf())
            session = currentSession
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }

        assertThat(currentSession.isInvalid).isFalse()
    }

    @Configuration
    @EnableWebSecurity
    open class InvalidateHttpSessionFalseConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    invalidateHttpSession = false
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when delete cookies then cookies are cleared`() {
        this.spring.register(DeleteCookiesConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
            cookie { maxAge("remove", 0) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DeleteCookiesConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    deleteCookies("remove")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when default logout success handler for request then custom handler used`() {
        this.spring.register(DefaultLogoutSuccessHandlerForConfig::class.java).autowire()

        this.mockMvc.post("/logout/default") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
        }

        this.mockMvc.post("/logout/custom") {
            with(csrf())
        }.andExpect {
            status { isFound() }
            redirectedUrl("/")
        }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultLogoutSuccessHandlerForConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    logoutRequestMatcher = AntPathRequestMatcher("/logout/**")
                    defaultLogoutSuccessHandlerFor(SimpleUrlLogoutSuccessHandler(), AntPathRequestMatcher("/logout/custom"))
                }
            }
            return http.build()
        }
    }

    @Test
    fun `logout when custom logout handler then custom handler used`() {
        this.spring.register(CustomLogoutHandlerConfig::class.java).autowire()
       mockkObject(CustomLogoutHandlerConfig.HANDLER)
        every { CustomLogoutHandlerConfig.HANDLER.logout(any(), any(), any()) } returns Unit

        this.mockMvc.post("/logout") {
            with(csrf())
        }

        verify(exactly = 1) { CustomLogoutHandlerConfig.HANDLER.logout(any(), any(), any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomLogoutHandlerConfig {

        companion object {
            val HANDLER: LogoutHandler = NoopLogoutHandler()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                logout {
                    addLogoutHandler(HANDLER)
                }
            }
            return http.build()
        }
    }

    class NoopLogoutHandler: LogoutHandler {
        override fun logout(
            request: HttpServletRequest?,
            response: HttpServletResponse?,
            authentication: Authentication?
        ) { }

    }
}
