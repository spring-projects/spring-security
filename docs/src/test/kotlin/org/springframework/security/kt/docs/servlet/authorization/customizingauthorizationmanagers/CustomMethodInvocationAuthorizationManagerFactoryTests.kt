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
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 * Tests for [CustomMethodInvocationAuthorizationManagerFactory].
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension::class)
class CustomMethodInvocationAuthorizationManagerFactoryTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    @Throws(Exception::class)
    fun getUserWhenAnonymousThenForbidden() {
        spring.register(SecurityConfiguration::class.java).autowire()
        // @formatter:off
        mockMvc.perform(get("/user").with(anonymous()))
            .andExpect(status().isForbidden())
            .andExpect(unauthenticated())
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenAuthenticatedWithNoRolesThenForbidden() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", listOf())
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenAuthenticatedWithUserRoleThenOk() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_USER")
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenAuthenticatedWithAdminRoleThenOk() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_ADMIN")
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenAuthenticatedWithOtherRoleThenForbidden() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_OTHER")
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getRolesWhenAuthenticatedWithRole1RoleThenOk() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_ROLE1")
        // @formatter:off
        mockMvc.perform(get("/roles").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getRolesWhenAuthenticatedWithAdminRoleThenOk() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_ADMIN")
        // @formatter:off
        mockMvc.perform(get("/roles").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getRolesWhenAuthenticatedWithOtherRoleThenForbidden() {
        spring.register(SecurityConfiguration::class.java).autowire()
        val authentication = TestingAuthenticationToken("user", "", "ROLE_OTHER")
        // @formatter:off
        mockMvc.perform(get("/roles").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @EnableWebMvc
    @EnableWebSecurity
    @EnableMethodSecurity
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
        open fun customMethodInvocationAuthorizationManagerFactory(): CustomMethodInvocationAuthorizationManagerFactory {
            return CustomMethodInvocationAuthorizationManagerFactory()
        }

        @Bean
        open fun testController(testService: TestService): TestController {
            return TestController(testService())
        }

        @Bean
        open fun testService(): TestService {
            return TestServiceImpl()
        }
    }

    @RestController
    internal open class TestController(private val testService: TestService) {
        @GetMapping("/user")
        @ResponseStatus(HttpStatus.OK)
        fun user() {
            testService.user()
        }

        @GetMapping("/roles")
        @ResponseStatus(HttpStatus.OK)
        fun roles() {
            testService.roles()
        }
    }

    internal interface TestService {
        @PreAuthorize("hasRole('USER')")
        fun user()

        @PreAuthorize("hasAnyRole('ROLE1', 'ROLE2')")
        fun roles()
    }

    internal open class TestServiceImpl : TestService {
        override fun user() {
        }

        override fun roles() {
        }
    }
}
