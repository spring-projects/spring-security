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
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
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

/**
 * Tests for [FormLoginDsl]
 *
 * @author Eleftheria Stein
 */
class FormLoginDslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

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

    @EnableWebSecurity
    open class FormLoginConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
            }
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

    @EnableWebSecurity
    open class AllSecuredConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
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

    @EnableWebSecurity
    open class LoginPageConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    loginPage = "/log-in"
                }
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
            }
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

    @EnableWebSecurity
    open class SuccessHandlerConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    authenticationSuccessHandler = SimpleUrlAuthenticationSuccessHandler("/success")
                }
            }
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

    @EnableWebSecurity
    open class FailureHandlerConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    authenticationFailureHandler = SimpleUrlAuthenticationFailureHandler("/failure")
                }
            }
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

    @EnableWebSecurity
    open class FailureUrlConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    failureUrl = "/failure"
                }
            }
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

    @EnableWebSecurity
    open class LoginProcessingUrlConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    loginProcessingUrl = "/custom"
                }
            }
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

    @EnableWebSecurity
    open class DefaultSuccessUrlConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {
                    defaultSuccessUrl("/custom", true)
                }
            }
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

    @EnableWebSecurity
    open class PermitAllConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                formLogin {
                    loginPage = "/custom/login"
                    permitAll()
                }
            }
        }

        @Controller
        class LoginController {
            @GetMapping("/custom/login")
            fun loginPage() {}
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
