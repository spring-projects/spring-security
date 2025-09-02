/*
 * Copyright 2004-present the original author or authors.
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
package org.springframework.security.kt.docs.servlet.authorization.customizingauthorizationmanagers

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 * Tests for [CustomHttpRequestsAuthorizationManagerFactory].
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension::class)
class CustomHttpRequestsAuthorizationManagerFactoryTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    @Throws(Exception::class)
    fun getHelloWhenAnonymousThenForbidden() {
        spring.register(SecurityConfiguration::class.java, TestController::class.java).autowire()
        // @formatter:off
        mockMvc.perform(get("/hello").with(anonymous()))
            .andExpect(status().isForbidden())
            .andExpect(SecurityMockMvcResultMatchers.unauthenticated())
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getHelloWhenAuthenticatedWithUserRoleThenOk() {
        spring.register(SecurityConfiguration::class.java, TestController::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_USER")
        // @formatter:off
        mockMvc.perform(get("/hello").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getHelloWhenAuthenticatedWithOtherRoleThenForbidden() {
        spring.register(SecurityConfiguration::class.java, TestController::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_OTHER")
        // @formatter:off
        mockMvc.perform(get("/hello").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getHelloWhenAuthenticatedWithNoRolesThenForbidden() {
        spring.register(SecurityConfiguration::class.java, TestController::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", listOf())
        // @formatter:off
        mockMvc.perform(get("/hello").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @EnableWebMvc
    @EnableWebSecurity
    @Configuration
    internal open class SecurityConfiguration {
        @Bean
        @Throws(Exception::class)
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            // @formatter:off
            http
                .authorizeHttpRequests { authorize ->
                    authorize.anyRequest().authenticated()
                }
            // @formatter:on
            return http.build()
        }

        @Bean
        open fun customHttpRequestsAuthorizationManagerFactory(): CustomHttpRequestsAuthorizationManagerFactory {
            return CustomHttpRequestsAuthorizationManagerFactory()
        }
    }

    @RestController
    internal class TestController {
        @GetMapping("/**")
        @ResponseStatus(HttpStatus.OK)
        fun ok() {
        }
    }
}
