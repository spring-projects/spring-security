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
package org.springframework.security.kt.docs.servlet.authorization.authzauthorizationmanagerfactory

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
import org.springframework.security.kt.docs.servlet.authorization.authzauthorizationmanagerfactory.AuthorizationManagerFactoryConfiguration.Anonymous
import org.springframework.security.kt.docs.servlet.authorization.authzauthorizationmanagerfactory.AuthorizationManagerFactoryConfiguration.RememberMe
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication
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
 * Tests for [AuthorizationManagerFactoryConfiguration].
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension::class)
class AuthorizationManagerFactoryConfigurationTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    @Throws(Exception::class)
    fun getAnonymousWhenCustomAnonymousClassThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = Anonymous("anonymous")
        // @formatter:off
        mockMvc.perform(get("/anonymous").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getAnonymousWhenAuthenticatedThenForbidden() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = TestingAuthenticationToken("user", "", "role_user")
        // @formatter:off
        mockMvc.perform(get("/anonymous").with(authentication(authentication)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getRememberMeWhenCustomRememberMeClassThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = RememberMe("rememberMe")
        // @formatter:off
        mockMvc.perform(get("/rememberMe").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getRememberMeWhenAuthenticatedThenForbidden() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val user = TestingAuthenticationToken("user", "", "role_user")
        // @formatter:off
        mockMvc.perform(get("/rememberMe").with(authentication(user)))
            .andExpect(status().isForbidden())
            .andExpect(authenticated().withAuthentication(user))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenCustomUserRoleThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = TestingAuthenticationToken("user", "", "role_user")
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getUserWhenCustomAdminRoleThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val admin = TestingAuthenticationToken("admin", "", "role_admin")
        // @formatter:off
        mockMvc.perform(get("/user").with(authentication(admin)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(admin))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getPreAuthorizeWhenCustomUserRoleThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = TestingAuthenticationToken("user", "", "role_user")
        // @formatter:off
        mockMvc.perform(get("/preAuthorize").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getPreAuthorizeWhenCustomAdminRoleThenOk() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = TestingAuthenticationToken("admin", "", "role_admin")
        // @formatter:off
        mockMvc.perform(get("/preAuthorize").with(authentication(authentication)))
            .andExpect(status().isOk())
            .andExpect(authenticated().withAuthentication(authentication))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getPreAuthorizeWhenOtherRoleThenForbidden() {
        this.spring.register(AuthorizationManagerFactoryConfiguration::class.java, SecurityConfiguration::class.java)
            .autowire()
        val authentication = TestingAuthenticationToken("other", "", "role_other")
        // @formatter:off
        mockMvc.perform(get("/preAuthorize").with(authentication(authentication)))
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
            http.authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/anonymous").anonymous()
                    .requestMatchers("/rememberMe").rememberMe()
                    .requestMatchers("/user").hasRole("user")
                    .requestMatchers("/preAuthorize").permitAll()
                    .anyRequest().denyAll()
            }
            // @formatter:on
            return http.build()
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
        @GetMapping(value = ["/anonymous", "/rememberMe", "/user"])
        @ResponseStatus(HttpStatus.OK)
        fun httpRequest() {
        }

        @GetMapping("/preAuthorize")
        @ResponseStatus(HttpStatus.OK)
        fun preAuthorize() {
            testService.preAuthorize()
        }
    }

    internal interface TestService {
        @PreAuthorize("hasRole('user')")
        fun preAuthorize()
    }

    internal open class TestServiceImpl : TestService {
        override fun preAuthorize() {
        }
    }
}
