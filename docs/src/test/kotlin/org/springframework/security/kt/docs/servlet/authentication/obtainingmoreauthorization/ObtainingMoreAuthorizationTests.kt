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
package org.springframework.security.kt.docs.servlet.authentication.obtainingmoreauthorization

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.docs.servlet.authentication.obtainingmoreauthorization.ScopeConfiguration
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
import org.springframework.test.context.TestExecutionListeners
import org.springframework.test.context.junit.jupiter.SpringExtension
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
@ExtendWith(SpringExtension::class, SpringTestContextExtension::class)
@TestExecutionListeners(WithSecurityContextTestExecutionListener::class)
class ObtainingMoreAuthorizationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    @Autowired
    var mockMvc: MockMvc? = null

    @Test
    @WithMockUser
    @Throws(Exception::class)
    fun profileWhenScopeConfigurationThenDenies() {
        this.spring.register(ScopeConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/profile"))
        .andExpect(MockMvcResultMatchers.status().isForbidden())
    		// @formatter:on
    }

    @Test
    @WithMockUser(authorities = [FactorGrantedAuthority.X509_AUTHORITY, FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY])
    @Throws(Exception::class)
    fun profileWhenMissingAuthorityConfigurationThenRedirectsToAuthorizationServer() {
        this.spring.register(MissingAuthorityConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/profile"))
        .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
        .andExpect(MockMvcResultMatchers.redirectedUrl("https://authz.example.org/authorize?scope=profile:read"))
    		// @formatter:on
    }

    @Test
    @WithMockUser(authorities = ["SCOPE_profile:read"])
    @Throws(Exception::class)
    fun profileWhenMissingX509WithOttThenForbidden() {
        this.spring.register(MissingAuthorityConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/profile"))
        .andExpect(MockMvcResultMatchers.status().isForbidden())
    		// @formatter:on
    }

    @Test
    @WithMockUser(authorities = [FactorGrantedAuthority.X509_AUTHORITY, FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY, "SCOPE_profile:read"])
    @Throws(
        Exception::class
    )
    fun profileWhenAuthenticatedAndHasScopeThenPermits() {
        this.spring.register(MissingAuthorityConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/profile"))
        .andExpect(MockMvcResultMatchers.status().isOk())
        .andExpect(SecurityMockMvcResultMatchers.authenticated().withUsername("user"))
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
