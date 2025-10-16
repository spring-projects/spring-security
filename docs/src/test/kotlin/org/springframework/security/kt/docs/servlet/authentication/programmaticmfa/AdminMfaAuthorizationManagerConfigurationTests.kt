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
package org.springframework.security.kt.docs.servlet.authentication.programmaticmfa

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.test.context.TestExecutionListeners
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Tests [CustomX509Configuration].
 *
 * @author Rob Winch
 */
@ExtendWith(SpringExtension::class, SpringTestContextExtension::class)
@TestExecutionListeners(WithSecurityContextTestExecutionListener::class)
class AdminMfaAuthorizationManagerConfigurationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    @Autowired
    var mockMvc: MockMvc? = null

    @Test
    @Throws(Exception::class)
    @WithMockUser(username = "admin")
    fun getWhenAdminThenRedirectsToOtt() {
        this.spring.register(AdminMfaAuthorizationManagerConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(get("/"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://localhost/login?factor.type=ott&factor.type=password&factor.reason=missing&factor.reason=missing"))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    @WithMockUser
    fun getWhenNotAdminThenAllows() {
        this.spring.register(AdminMfaAuthorizationManagerConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(authenticated().withUsername("user"))
    	// @formatter:on
    }

    @Test
    @Throws(Exception::class)
    @WithMockUser(username = "admin", authorities = [FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY])
    fun getWhenAdminAndHasFactorThenAllows() {
        this.spring.register(AdminMfaAuthorizationManagerConfiguration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(authenticated().withUsername("admin"))
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
