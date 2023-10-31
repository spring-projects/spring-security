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
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.User
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Controller
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.annotation.Bean
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource

/**
 * Tests for [FormLoginDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class FormLoginDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `login page when form login configured then default login page created`() {
        this.spring.register(FormLoginConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.get("/login")
                .andExpect {
                    status { isOk() }
                }
    }

    @Test
    fun `login when success then redirects to home`() {
        this.spring.register(FormLoginConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin())
                .andExpect {
                    status().isFound
                    redirectedUrl("/")
                }
    }

    @Test
    fun `login when failure then redirects to login page with error`() {
        this.spring.register(FormLoginConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin().password("invalid"))
                .andExpect {
                    status().isFound
                    redirectedUrl("/login?error")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class FormLoginConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {}
            }
            return http.build()
        }
    }

    @Test
    fun `request when secure then redirects to default login page`() {
        this.spring.register(AllSecuredConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("http://localhost/login")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class AllSecuredConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {}
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @Test
    fun `request when secure and custom login page then redirects to custom login page`() {
        this.spring.register(LoginPageConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.get("/")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("http://localhost/log-in")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class LoginPageConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    loginPage = "/log-in"
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when custom success handler then used`() {
        this.spring.register(SuccessHandlerConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin())
                .andExpect {
                    status().isFound
                    redirectedUrl("/success")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class SuccessHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    authenticationSuccessHandler = SimpleUrlAuthenticationSuccessHandler("/success")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when custom failure handler then used`() {
        this.spring.register(FailureHandlerConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin().password("invalid"))
                .andExpect {
                    status().isFound
                    redirectedUrl("/failure")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class FailureHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    authenticationFailureHandler = SimpleUrlAuthenticationFailureHandler("/failure")
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when custom failure url then used`() {
        this.spring.register(FailureHandlerConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin().password("invalid"))
                .andExpect {
                    status().isFound
                    redirectedUrl("/failure")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class FailureUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    failureUrl = "/failure"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when custom login processing url then used`() {
        this.spring.register(LoginProcessingUrlConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin("/custom"))
                .andExpect {
                    status().isFound
                    redirectedUrl("/")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class LoginProcessingUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    loginProcessingUrl = "/custom"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when default success url then redirected to url`() {
        this.spring.register(DefaultSuccessUrlConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.perform(formLogin())
                .andExpect {
                    status().isFound
                    redirectedUrl("/custom")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class DefaultSuccessUrlConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    defaultSuccessUrl("/custom", true)
                }
            }
            return http.build()
        }
    }

    @Test
    fun `login when permit all then login page not protected`() {
        this.spring.register(PermitAllConfig::class.java, UserConfig::class.java).autowire()

        this.mockMvc.get("/custom/login")
                .andExpect {
                    status { isOk() }
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
                formLogin {
                    loginPage = "/custom/login"
                    permitAll()
                }
            }
            return http.build()
        }

        @Controller
        class LoginController {
            @GetMapping("/custom/login")
            fun loginPage() {}
        }
    }

    @Test
    fun `form login when custom authentication details source then used`() {
        this.spring
            .register(CustomAuthenticationDetailsSourceConfig::class.java, UserConfig::class.java)
            .autowire()
        mockkObject(CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE)
        every {
            CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE.buildDetails(any())
        } returns mockk()

        this.mockMvc.perform(formLogin())
            .andExpect {
                status().isFound
                redirectedUrl("/")
            }

        verify(exactly = 1) { CustomAuthenticationDetailsSourceConfig.AUTHENTICATION_DETAILS_SOURCE.buildDetails(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class CustomAuthenticationDetailsSourceConfig {

        companion object {
            val AUTHENTICATION_DETAILS_SOURCE = WebAuthenticationDetailsSource()
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                formLogin {
                    authenticationDetailsSource = AUTHENTICATION_DETAILS_SOURCE
                }
            }
            return http.build()
        }
    }

    @Configuration
    open class UserConfig {
        @Autowired
        fun configureGlobal(auth: AuthenticationManagerBuilder) {
            auth
                    .inMemoryAuthentication()
                    .withUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER"))
        }
    }
}
