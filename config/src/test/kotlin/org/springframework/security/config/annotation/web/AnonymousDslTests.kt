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
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import java.util.*

/**
 * Tests for [AnonymousDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class AnonymousDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `anonymous when custom principal then custom principal used`() {
        this.spring.register(PrincipalConfig::class.java, PrincipalController::class.java).autowire()

        this.mockMvc.get("/principal")
                .andExpect {
                    content { string("principal") }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class PrincipalConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                anonymous {
                    principal = "principal"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `anonymous when custom key then custom key used`() {
        this.spring.register(KeyConfig::class.java, PrincipalController::class.java).autowire()

        this.mockMvc.get("/key")
                .andExpect {
                    content { string("key".hashCode().toString()) }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class KeyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                anonymous {
                    key = "key"
                }
            }
            return http.build()
        }
    }

    @Test
    fun `anonymous when disabled then responds with forbidden`() {
        this.spring.register(AnonymousDisabledConfig::class.java, PrincipalController::class.java).autowire()

        this.mockMvc.get("/principal")
                .andExpect {
                    content { string("") }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AnonymousDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                anonymous {
                    disable()
                }
            }
            return http.build()
        }
    }

    @Test
    fun `anonymous when custom authorities then authorities used`() {
        this.spring.register(AnonymousAuthoritiesConfig::class.java, PrincipalController::class.java).autowire()

        this.mockMvc.get("/principal")
                .andExpect {
                    status { isOk() }
                }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AnonymousAuthoritiesConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                anonymous {
                    authorities = listOf(SimpleGrantedAuthority("TEST"))
                }
                authorizeRequests {
                    authorize(anyRequest, hasAuthority("TEST"))
                }
            }
            return http.build()
        }
    }

    @RestController
    internal class PrincipalController {
        @GetMapping("/principal")
        fun principal(@AuthenticationPrincipal principal: String?): String? {
            return principal
        }

        @GetMapping("/key")
        fun key(): String {
            return anonymousToken()
                    .map { it.keyHash }
                    .map { it.toString() }
                    .orElse(null)
        }

        private fun anonymousToken(): Optional<AnonymousAuthenticationToken> {
            return Optional.of(SecurityContextHolder.getContext())
                    .map { it.authentication }
                    .filter { it is AnonymousAuthenticationToken }
                    .map { AnonymousAuthenticationToken::class.java.cast(it) }
        }
    }
}
