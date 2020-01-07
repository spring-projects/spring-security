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

import org.assertj.core.api.Assertions.assertThat
import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
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
class LogoutDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `logout when custom logout url then custom url used`() {
        this.spring.register(CustomLogoutUrlConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login?logout")
        }
    }

    @EnableWebSecurity
    open class CustomLogoutUrlConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    logoutUrl = "/custom/logout"
                }
            }
        }
    }

    @Test
    fun `logout when custom logout request matcher then custom request matcher used`() {
        this.spring.register(CustomLogoutRequestMatcherConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login?logout")
        }
    }

    @EnableWebSecurity
    open class CustomLogoutRequestMatcherConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    logoutRequestMatcher = AntPathRequestMatcher("/custom/logout")
                }
            }
        }
    }

    @Test
    fun `logout when custom success url then redirects to success url`() {
        this.spring.register(SuccessUrlConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login")
        }
    }

    @EnableWebSecurity
    open class SuccessUrlConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    logoutSuccessUrl = "/login"
                }
            }
        }
    }

    @Test
    fun `logout when custom success handler then redirects to success url`() {
        this.spring.register(SuccessHandlerConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/")
        }
    }

    @EnableWebSecurity
    open class SuccessHandlerConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    logoutSuccessHandler = SimpleUrlLogoutSuccessHandler()
                }
            }
        }
    }

    @Test
    fun `logout when permit all then logout allowed`() {
        this.spring.register(PermitAllConfig::class.java).autowire()

        this.mockMvc.post("/custom/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login?logout")
        }
    }

    @EnableWebSecurity
    open class PermitAllConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                logout {
                    logoutUrl = "/custom/logout"
                    permitAll()
                }
            }
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
            status { isFound }
            redirectedUrl("/login?logout")
        }

        assertThat(currentContext.authentication).isNotNull
    }

    @EnableWebSecurity
    open class ClearAuthenticationFalseConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    clearAuthentication = false
                }
            }
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
            status { isFound }
            redirectedUrl("/login?logout")
        }

        assertThat(currentSession.isInvalid).isFalse()
    }

    @EnableWebSecurity
    open class InvalidateHttpSessionFalseConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    invalidateHttpSession = false
                }
            }
        }
    }

    @Test
    fun `logout when delete cookies then cookies are cleared`() {
        this.spring.register(DeleteCookiesConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login?logout")
            cookie { maxAge("remove", 0) }
        }
    }

    @EnableWebSecurity
    open class DeleteCookiesConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    deleteCookies("remove")
                }
            }
        }
    }

    @Test
    fun `logout when default logout success handler for request then custom handler used`() {
        this.spring.register(DefaultLogoutSuccessHandlerForConfig::class.java).autowire()

        this.mockMvc.post("/logout/default") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/login?logout")
        }

        this.mockMvc.post("/logout/custom") {
            with(csrf())
        }.andExpect {
            status { isFound }
            redirectedUrl("/")
        }
    }

    @EnableWebSecurity
    open class DefaultLogoutSuccessHandlerForConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    logoutRequestMatcher = AntPathRequestMatcher("/logout/**")
                    defaultLogoutSuccessHandlerFor(SimpleUrlLogoutSuccessHandler(), AntPathRequestMatcher("/logout/custom"))
                }
            }
        }
    }

    @Test
    fun `logout when custom logout handler then custom handler used`() {
        this.spring.register(CustomLogoutHandlerConfig::class.java).autowire()

        this.mockMvc.post("/logout") {
            with(csrf())
        }

        verify(CustomLogoutHandlerConfig.HANDLER).logout(any(), any(), any())
    }

    @EnableWebSecurity
    open class CustomLogoutHandlerConfig : WebSecurityConfigurerAdapter() {
        companion object {
            var HANDLER: LogoutHandler = mock(LogoutHandler::class.java)
        }

        override fun configure(http: HttpSecurity) {
            http {
                logout {
                    addLogoutHandler(HANDLER)
                }
            }
        }
    }
}
