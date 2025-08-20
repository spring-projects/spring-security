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
package org.springframework.security.kt.docs.servlet.configuration.dslbeanordering

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.kt.docs.servlet.configuration.customizerbeanordering.CustomizerBeanOrderingConfiguration
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 *
 */
@ExtendWith(SpringTestContextExtension::class)
class DslBeanOrderingTests {
    @JvmField
    val spring = SpringTestContext(this).mockMvcAfterSpringSecurityOk()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun dslOrdered() {
        this.spring.register(DslBeanOrderingConfiguration::class.java).autowire()
        // @formatter:off
        this.mockMvc.get("https://localhost/admins/1") {
            with(user("admin").roles("ADMIN"))
        }.andExpect {
            status { isOk() }
        }
        this.mockMvc.get("https://localhost/admins/1") {
            with(user("user").roles("USER"))
        }.andExpect {
            status { isForbidden() }
        }
        this.mockMvc.get("https://localhost/users/1") {
            with(user("user").roles("USER"))
        }.andExpect {
            status { isOk() }
        }
        this.mockMvc.get("https://localhost/users/1") {
            with(user("noUserRole").roles("OTHER"))
        }.andExpect {
            status { isForbidden() }
        }
        this.mockMvc.get("https://localhost/other") {
            with(user("authenticated").roles("OTHER"))
        }.andExpect {
            status { isOk() }
        }
        // @formatter:on
    }
}
