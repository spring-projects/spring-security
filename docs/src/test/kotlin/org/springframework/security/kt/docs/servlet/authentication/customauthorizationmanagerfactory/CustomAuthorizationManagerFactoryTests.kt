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
package org.springframework.security.kt.docs.servlet.authentication.customauthorizationmanagerfactory

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Tests [CustomX509Configuration].
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension::class)
class CustomAuthorizationManagerFactoryTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    @Autowired
    var mockMvc: MockMvc? = null

    @Autowired
    var users: UserDetailsService? = null

    @Test
    @Throws(Exception::class)
    fun getWhenOptedInThenRedirectsToOtt() {
        this.spring.register(CustomAuthorizationManagerFactory::class.java, Http200Controller::class.java).autowire()
        val user = this.users!!.loadUserByUsername("optedin")
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/").with(SecurityMockMvcRequestPostProcessors.user(user)))
        .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
        .andExpect(MockMvcResultMatchers.redirectedUrl("http://localhost/login?factor=ott"))
    		// @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getWhenNotOptedInThenAllows() {
        this.spring.register(CustomAuthorizationManagerFactory::class.java, Http200Controller::class.java).autowire()
        val user = this.users!!.loadUserByUsername("user")
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/").with(SecurityMockMvcRequestPostProcessors.user(user)))
        .andExpect(MockMvcResultMatchers.status().isOk())
        .andExpect(SecurityMockMvcResultMatchers.authenticated().withUsername("user"))
    		// @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun getWhenOptedAndHasFactorThenAllows() {
        this.spring.register(CustomAuthorizationManagerFactory::class.java, Http200Controller::class.java).autowire()
        val user = this.users!!.loadUserByUsername("optedin")
        val token = TestingAuthenticationToken(user, "", "FACTOR_OTT")
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/").with(SecurityMockMvcRequestPostProcessors.authentication(token)))
        .andExpect(MockMvcResultMatchers.status().isOk())
        .andExpect(SecurityMockMvcResultMatchers.authenticated().withUsername("optedin"))
    		// @formatter:on
    }

    @RestController
    internal class Http200Controller {
        @GetMapping("/**")
        fun ok(): String {
            return "ok"
        }
    }
}
