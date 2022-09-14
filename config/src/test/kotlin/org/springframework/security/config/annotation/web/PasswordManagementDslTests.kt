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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [PasswordManagementDsl].
 *
 * @author Evgeniy Cheban
 */
@ExtendWith(SpringTestContextExtension::class)
class PasswordManagementDslTests {

    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `when change password page not set then default change password page used`() {
        this.spring.register(PasswordManagementWithDefaultChangePasswordPageConfig::class.java).autowire()

        this.mockMvc.get("/.well-known/change-password")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("/change-password")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class PasswordManagementWithDefaultChangePasswordPageConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                passwordManagement {}
            }
            return http.build()
        }
    }

    @Test
    fun `when change password page set then specified change password page used`() {
        this.spring.register(PasswordManagementWithCustomChangePasswordPageConfig::class.java).autowire()

        this.mockMvc.get("/.well-known/change-password")
                .andExpect {
                    status { isFound() }
                    redirectedUrl("/custom-change-password-page")
                }
    }

    @Configuration
    @EnableWebSecurity
    open class PasswordManagementWithCustomChangePasswordPageConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                passwordManagement {
                    changePasswordPage = "/custom-change-password-page"
                }
            }
            return http.build()
        }
    }
}
