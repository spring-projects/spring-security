/*
 * Copyright 2002-2024 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.PasswordEncodedUser
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers

/**
 * Tests for [OneTimeTokenLoginDsl]
 *
 * @author Max Batischev
 */
@ExtendWith(SpringTestContextExtension::class)
class OneTimeTokenLoginDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun `oneTimeToken when correct token then can authenticate`() {
        spring.register(OneTimeTokenConfig::class.java).autowire()
        this.mockMvc.perform(
            MockMvcRequestBuilders.post("/ott/generate").param("username", "user")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        ).andExpectAll(
            MockMvcResultMatchers
                .status()
                .isFound(),
            MockMvcResultMatchers
                .redirectedUrl("/login/ott")
        )

        val token = TestOneTimeTokenGenerationSuccessHandler.lastToken?.tokenValue

        this.mockMvc.perform(
            MockMvcRequestBuilders.post("/login/ott").param("token", token)
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
            .andExpectAll(
                MockMvcResultMatchers.status().isFound(),
                MockMvcResultMatchers.redirectedUrl("/"),
                SecurityMockMvcResultMatchers.authenticated()
            )
    }

    @Test
    fun `oneTimeToken when different authentication urls then can authenticate`() {
        spring.register(OneTimeTokenDifferentUrlsConfig::class.java).autowire()
        this.mockMvc.perform(
            MockMvcRequestBuilders.post("/generateurl").param("username", "user")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
            .andExpectAll(MockMvcResultMatchers.status().isFound(), MockMvcResultMatchers.redirectedUrl("/redirected"))

        val token = TestOneTimeTokenGenerationSuccessHandler.lastToken?.tokenValue

        this.mockMvc.perform(
            MockMvcRequestBuilders.post("/loginprocessingurl").param("token", token)
                .with(SecurityMockMvcRequestPostProcessors.csrf())
        )
            .andExpectAll(
                MockMvcResultMatchers.status().isFound(),
                MockMvcResultMatchers.redirectedUrl("/authenticated"),
                SecurityMockMvcResultMatchers.authenticated()
            )
    }

    @Configuration
    @EnableWebSecurity
    @Import(UserDetailsServiceConfig::class)
    open class OneTimeTokenConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            // @formatter:off
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
                oneTimeTokenLogin {
                    oneTimeTokenGenerationSuccessHandler = TestOneTimeTokenGenerationSuccessHandler()
                }
            }
            // @formatter:on
            return http.build()
        }
    }

    @EnableWebSecurity
    @Configuration(proxyBeanMethods = false)
    @Import(UserDetailsServiceConfig::class)
    open class OneTimeTokenDifferentUrlsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            // @formatter:off
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
                oneTimeTokenLogin {
                    tokenGeneratingUrl = "/generateurl"
                    oneTimeTokenGenerationSuccessHandler = TestOneTimeTokenGenerationSuccessHandler("/redirected")
                    loginProcessingUrl = "/loginprocessingurl"
                    authenticationSuccessHandler = SimpleUrlAuthenticationSuccessHandler("/authenticated")
                }
            }
            // @formatter:on
            return http.build()
        }
    }

    @Configuration(proxyBeanMethods = false)
    open class UserDetailsServiceConfig {

        @Bean
        open fun userDetailsService(): UserDetailsService =
            InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin())
    }

    private class TestOneTimeTokenGenerationSuccessHandler :
        OneTimeTokenGenerationSuccessHandler {
        private val delegate: OneTimeTokenGenerationSuccessHandler

        constructor() {
            this.delegate =
                RedirectOneTimeTokenGenerationSuccessHandler(
                    "/login/ott"
                )
        }

        constructor(redirectUrl: String?) {
            this.delegate =
                RedirectOneTimeTokenGenerationSuccessHandler(
                    redirectUrl
                )
        }

        override fun handle(request: HttpServletRequest, response: HttpServletResponse, oneTimeToken: OneTimeToken) {
            lastToken = oneTimeToken
            delegate.handle(request, response, oneTimeToken)
        }

        companion object {
            var lastToken: OneTimeToken? = null
        }
    }
}
