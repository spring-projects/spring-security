/*
 * Copyright 2002-2025 the original author or authors.
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
package org.springframework.security.kt.docs.servlet.authentication.servlet509config

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Tests [CustomX509Configuration].
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension::class)
class X509ConfigurationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    @Autowired
    var mockMvc: MockMvc? = null

    @Test
    @Throws(Exception::class)
    fun x509WhenDefaultX509Configuration() {
        this.spring.register(DefaultX509Configuration::class.java, Http200Controller::class.java).autowire()
        // @formatter:off
        this.mockMvc!!.perform(get("/").with(SecurityMockMvcRequestPostProcessors.x509("rod.cer")))
            .andExpect(status().isOk())
            .andExpect(authenticated().withUsername("rod"))
        // @formatter:on
    }

    @Test
    @Throws(Exception::class)
    fun x509WhenCustomX509Configuration() {
        this.spring.register(CustomX509Configuration::class.java, Http200Controller::class.java).autowire()
        val certificate = X509TestUtils.buildTestCertificate()
        // @formatter:off
        this.mockMvc!!.perform(get("/").with(SecurityMockMvcRequestPostProcessors.x509(certificate)))
        .andExpect(status().isOk())
        .andExpect(authenticated().withUsername("luke@monkeymachine"))
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
