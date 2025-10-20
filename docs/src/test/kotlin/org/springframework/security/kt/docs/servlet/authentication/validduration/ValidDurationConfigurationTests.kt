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
package org.springframework.security.kt.docs.servlet.authentication.validduration

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
import org.springframework.test.context.TestExecutionListeners
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.request.RequestPostProcessor
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 * Tests [CustomX509Configuration].
 *
 * @author Rob Winch
 */
@ExtendWith(SpringExtension::class, SpringTestContextExtension::class)
@TestExecutionListeners(WithSecurityContextTestExecutionListener::class)
class ValidDurationConfigurationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    @Autowired
    var mockMvc: MockMvc? = null

    @Test
    @Throws(Exception::class)
    fun adminWhenExpiredThenRequired() {
        this.spring.register(
            ValidDurationConfiguration::class.java, Http200Controller::class.java
        ).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/admin/").with(admin(Duration.ofMinutes(31))))
            .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
            .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login?*"))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun adminWhenNotExpiredThenOk() {
        this.spring.register(
            ValidDurationConfiguration::class.java, Http200Controller::class.java
        ).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/admin/").with(admin(Duration.ofMinutes(29))))
            .andExpect(MockMvcResultMatchers.status().isOk())
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun settingsWhenExpiredThenRequired() {
        this.spring.register(
            ValidDurationConfiguration::class.java, Http200Controller::class.java
        ).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/user/settings").with(user(Duration.ofMinutes(61))))
            .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
            .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login?*"))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun settingsWhenNotExpiredThenOk() {
        this.spring.register(
            ValidDurationConfiguration::class.java, ValidDurationConfigurationTests.Http200Controller::class.java
        ).autowire()
        // @formatter:off
        this.mockMvc!!.perform(MockMvcRequestBuilders.get("/user/settings").with(user(Duration.ofMinutes(59))))
            .andExpect(MockMvcResultMatchers.status().isOk())
        // @formatter:on
    }

    private fun admin(sinceAuthn: Duration): RequestPostProcessor {
        return authn("admin", sinceAuthn)
    }

    private fun user(sinceAuthn: Duration): RequestPostProcessor {
        return authn("user", sinceAuthn)
    }

    private fun authn(username: String, sinceAuthn: Duration): RequestPostProcessor {
        val issuedAt = Instant.now().minus(sinceAuthn)
        val factor = FactorGrantedAuthority
            .withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
            .issuedAt(issuedAt)
            .build()
        val role = username.uppercase(Locale.getDefault())
        val authn = TestingAuthenticationToken(
            username, "",
            factor, SimpleGrantedAuthority("ROLE_" + role)
        )
        return SecurityMockMvcRequestPostProcessors.authentication(authn)
    }

    @RestController
    internal class Http200Controller {
        @GetMapping("/**")
        fun ok(): String {
            return "ok"
        }
    }
}
